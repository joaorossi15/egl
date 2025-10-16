# EGL - Ethical Guardrail Language

A simple domain specific-language for ethical guardrails related to modular ethical principles for AI conversations (working with privacy and non-maleficence at the moment).

## Example EGL Syntax
```egl
policy p1(pre, post):
  forbid: self_harm
  redact: email "*"
  append: ip "Do not attempt to access this IP."
end
```

## Build 
Requirements: 
- GCC or Clange
- Make

Compile with `make`
- `make`

Clean files with `make`:
- `make clean`

## Execute
Run EGL with a source file .egl:
- `./egl path/to/source.egl`

