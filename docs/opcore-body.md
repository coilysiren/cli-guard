# Body projection and pinned values

How an inline grant shapes the body it sends: `map` renames caller input, `set` pins what the caller may not touch, and the two combine.

## `map` projects caller input

`map "commonAnnotations.summary" to="text"` projects required nested string inputs onto fresh top-level keys, forwards nothing else, and resolves to strings only. It cannot combine with body fields, a caller-named key and a mapped one both coming from the model, so which wins at a shared name has no single reading.

Renaming exists because an upstream's required parameter may collide with a reserved engine flag such as `query`. Mapping it is the only way to expose it under a name the caller can state.

## `set` pins what the caller cannot

`set k=v` states a scalar, all a KDL property holds. `set { ... }` carries a shape: one node per key, one argument, several for an array, or a block for an object, nesting as deep as needed.

```kdl
set numResults=5 { contents { text #true }; categories "news" "papers" }
```

**A pinned key never enters the input schema**, so the model can neither name nor vary it. That is what separates a pin from a field, and it matters most where a parameter drives cost. A key given twice, one with no value, one carrying both a value and a block, and `key=value` inside the block each have no single reading and fail closed.

## The two together

A pin seeds the projected body, so a grant needing both a renamed input and a fixed upstream parameter states each with the node built for it:

```kdl
can search result {
    path "/search"
    body { map "search_text" to="query" }
    set { contents { text #true } }
}
```

**One key cannot be both pinned and mapped**, which fails closed rather than picking a silent winner. Absence remains the stronger control where the wanted value is already the upstream default; a pin is for the value that is not.

Alone on a leaf that declares no `body` fields, `set` owns the body outright, which is the state-toggle shape: the caller's body is discarded rather than merged.

## `set` beside declared body fields

A leaf may declare body fields and pin others. The caller fills the declared fields, those are validated as usual, and the pins are laid over the result, the same precedence a mapped body gets. So a grant can expose the inputs a model needs while fixing an argument the model must not reach.

The pinned name simply goes undeclared. It never enters the input schema, so a caller cannot supply it and the pin has nothing to win against.

```kdl
can create record {
    path "/table/{tableId}/record"
    body {
        field "fieldKeyType" type="string"
        array "records" raw=true required=true
    }
    set typecast=false
}
```

Before this, declaring both silently discarded every declared field at request time: the pin replaced the whole body and the caller's input never left the process. Nothing warned, because the guardfile parsed clean.

## What the command line cannot do

A mapped source mounts no CLI flag, so `umbra` refuses a mapped-body grant rather than sending a body missing its mapped keys. Those grants are reached through the MCP surface, which carries nested inputs.
