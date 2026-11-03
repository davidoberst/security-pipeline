"""MUESTRA FICTICIA — laboratorio del pipeline de seguridad.
La "API key" es inventada (formato ALOLAB_ propio del lab): no da acceso a nada.
Existe solo para verificar que Gitleaks detecta secretos hardcodeados."""

PAYMENTS_API_KEY = "ALOLAB_7Q2X9KD4M1ZP8RT5VW3NB6HC0YJ2LF9G"  # FICTICIA


def cliente_demo():
    return {"api_key": PAYMENTS_API_KEY}
