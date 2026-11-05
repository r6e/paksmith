# Property serialization

Inside every `UObject` export body is a stream of properties. UE has two
serialization modes:

- **Tagged properties**. Each property carries a name + type tag on the
  wire, so the reader can iterate without a schema.
- **Unversioned properties**. The wire form is a compact bitstream + raw
  bodies that only decode when paired with the originating class layout.

The `primitives.md`, `containers.md`, `struct.md`, and `text.md` docs cover
the per-type wire bodies that both serialization modes share once a property
has been located.
