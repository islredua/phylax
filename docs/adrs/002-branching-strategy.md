# ADR-002: Estrategia de ramas (trunk-based)

**Fecha:** 2026-10-11
**Estado:** Aceptado

## Contexto

Proyecto de equipo unipersonal con cronograma de 12 semanas. La estrategia de ramas debe minimizar overhead sin sacrificar la trazabilidad de cambios ni la capacidad de revertir.

## Decisión

**Trunk-based development** sobre `main`.

### Reglas

1. **Rama única de larga vida:** `main`.
2. **Trabajo diario en ramas de feature cortas** (`feat/`, `fix/`, `docs/`, `refactor/`, `test/`) con vida máxima de 2-3 días.
3. **PRs obligatorios a `main`** — no se permite push directo.
4. **Protección de `main`:**
   - Require pull request before merging
   - Require status checks to pass (CI verde)
   - Dismiss stale approvals automatically
   - Require conversation resolution
5. **Squash merge por defecto** — cada feature queda como un commit limpio en `main`.
6. **Conventional Commits** para el título del PR y del squash commit:
   - `feat: scope — descripción`
   - `fix: scope — descripción`
   - `docs: ...`
   - `refactor: ...`
   - `test: ...`
   - `chore: ...`

### Ejemplo de ciclo

```
# Nueva feature
git checkout main && git pull
git checkout -b feat/scanners-nmap-wrapper

# Trabajar, hacer commits locales
git commit -am "wip: nmap XML parsing"

# Push y abrir PR
git push origin feat/scanners-nmap-wrapper
# gh pr create --title "feat: scanners — nmap wrapper + normalizer"

# Esperar CI verde, hacer merge en GitHub
# Rama local se puede borrar
git checkout main && git pull
git branch -D feat/scanners-nmap-wrapper
```

### Releases

- Tags semánticos (`v0.1.0`, `v0.2.0`...) marcan hitos del cronograma.
- `v0.1.0` = fin de Fase 1 (setup + skeleton funcional)
- `v0.2.0` = fin de Módulo 1
- ...
- `v1.0.0` = integración end-to-end antes de los experimentos

## Alternativa descartada: git-flow

Con `develop` + `main` + `release/` + `hotfix/`. Descartada por overhead injustificado para equipo unipersonal y ciclo corto.

## Consecuencias

- Historia de `main` siempre deployable
- CI debe ser rápida (< 3 min) para no ralentizar iteraciones
- No hay "staging" ni "preprod" en el flow — se compensa con el entorno sintético local
