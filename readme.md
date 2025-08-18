# EGL - Ethical Guardrail Language

A simple and easy to learn domain specific-language for ethical guardrails related to fairness and non-maleficence for AI conversations.

This project is the **compiler front-end** for EGL, implemented in C, including a **lexer**, **parser**, and **executor** (in progress).

## Example EGL Syntax
```egl
policy p1("pre", "post"):
  forbid: hate_speech
  refusal: discrimination
  redact: personal_data "***", names "---"
  append: medical_rec "Remember to be respectful."
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

