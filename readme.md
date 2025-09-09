# EGL - Ethical Guardrail Language

A simple domain specific-language for ethical guardrails related to modular ethical principles for AI conversations (working with fairness and non-maleficence at the moment).

## Example EGL Syntax
```egl
policy p1(pre, post):
  forbid: hate_speech
  redact: privacy "---"
  append: medical_risk "Remember to be respectful."
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

