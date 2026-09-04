# Plugin-pack security fixtures

`good/` is a data-only pack. Tests derive malicious variants from it so every
fixture remains small and each rejection isolates one boundary: path escape,
symlink traversal, duplicate ID, capability escalation, digest drift,
incompatible component versions, an undeclared entry point, and an undeclared
Python import. None of these packs is imported or executed.
