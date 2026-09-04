;; A future adapter must reject this module before instantiation because the
;; network interface is absent from the typed read-only capability manifest.
(module
  (type $connect_t (func (param i32 i32) (result i32)))
  (import "mulder:capabilities/network" "connect" (func $connect (type $connect_t)))
  (memory (export "memory") 1 1)
  (func (export "run") (result i32)
    i32.const 0
    i32.const 0
    call $connect))
