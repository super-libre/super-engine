// SPDX-License-Identifier: GPL-3.0-only
//! Checks on the `OpenAPI` document a daemon generates from its router.

use utoipa::openapi::OpenApi;

/// Every `#/components/schemas/<name>` reference in `doc` that names no
/// schema in its components, sorted and deduplicated.
///
/// A daemon's document is assembled from its routes, and utoipa registers a
/// schema only when some route or the daemon's `ApiDoc` reaches it by name.
/// A type reached any other way — flattened into its parent, or through a
/// type parameter, as the shared registry types are — is referenced without
/// being registered, and a client generating code from the document then
/// finds a type that does not exist. A daemon's tests assert this is empty.
///
/// # Panics
/// If `doc` does not serialize, which a document utoipa built always does.
#[must_use]
pub fn dangling_refs(doc: &OpenApi) -> Vec<String> {
    let value = serde_json::to_value(doc).expect("an OpenAPI document serializes");
    let known = value
        .pointer("/components/schemas")
        .and_then(serde_json::Value::as_object);
    let mut refs = Vec::new();
    collect_schema_refs(&value, &mut refs);
    let mut dangling: Vec<String> = refs
        .into_iter()
        .filter(|name| !known.is_some_and(|schemas| schemas.contains_key(name)))
        .collect();
    dangling.sort();
    dangling.dedup();
    dangling
}

/// The schema names every `$ref` in `value` points at.
fn collect_schema_refs(value: &serde_json::Value, out: &mut Vec<String>) {
    match value {
        serde_json::Value::Object(map) => {
            for (key, child) in map {
                if key == "$ref"
                    && let Some(name) = child
                        .as_str()
                        .and_then(|target| target.strip_prefix("#/components/schemas/"))
                {
                    out.push(name.to_string());
                } else {
                    collect_schema_refs(child, out);
                }
            }
        }
        serde_json::Value::Array(items) => {
            for item in items {
                collect_schema_refs(item, out);
            }
        }
        _ => {}
    }
}

#[cfg(test)]
mod tests {
    use super::dangling_refs;
    use utoipa::OpenApi as _;
    use utoipa::ToSchema;

    #[derive(ToSchema)]
    #[allow(dead_code)]
    struct Leaf {
        name: String,
    }

    #[derive(ToSchema)]
    #[allow(dead_code)]
    struct Listing<L> {
        leaves: Vec<L>,
    }

    type ProductListing = Listing<Leaf>;

    #[utoipa::path(get, path = "/list", responses((status = 200, body = ProductListing)))]
    #[allow(dead_code)]
    fn list() {}

    /// The case this exists for: a type reached only through a type
    /// parameter is referenced but never registered.
    #[test]
    fn a_type_reached_through_a_parameter_dangles() {
        #[derive(utoipa::OpenApi)]
        #[openapi(paths(list))]
        struct Doc;
        assert_eq!(dangling_refs(&Doc::openapi()), vec!["Leaf".to_string()]);
    }

    /// Registering it by name is the fix.
    #[test]
    fn a_registered_type_does_not_dangle() {
        #[derive(utoipa::OpenApi)]
        #[openapi(paths(list), components(schemas(Leaf)))]
        struct Doc;
        assert!(dangling_refs(&Doc::openapi()).is_empty());
    }
}
