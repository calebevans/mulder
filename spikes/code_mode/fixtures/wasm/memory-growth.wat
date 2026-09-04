;; A future adapter must reject or trap growth beyond its fixed memory budget.
(module
  (memory 1 65535)
  (func (export "run")
    (loop $grow
      i32.const 1
      memory.grow
      drop
      br $grow)))
