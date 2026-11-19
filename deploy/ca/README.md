Autoridades certificadoras propias de la organización (opcional).

Si el servidor de correo presenta un certificado firmado por la CA interna, deja aquí el
certificado de esa CA (solo el certificado, en PEM; nunca una llave privada) y dilo en `.env`:

    DJANGO_EMAIL_CA_FILE=/ca/ca-interna.pem

La carpeta se monta de solo lectura en `/ca` dentro del backend y de los trabajadores. Los
archivos no se versionan (solo este texto). Ver «Correo» en `docs/operacion.md`.
