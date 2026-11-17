Certificado de la organización para el perfil de producción (opcional).

Deja aquí el certificado y su llave y dilo en `.env`:

    ATALAYA_TLS="/certs/atalaya.crt /certs/atalaya.key"

Los archivos de esta carpeta no se versionan (solo este texto). Sin ellos el proxy usa la
autoridad interna de Caddy. Ver `docs/operacion.md`.
