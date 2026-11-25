# filevault

Un script pequeño para cifrar un archivo con una contraseña y volver a abrirlo después, todo desde la terminal. Usa AES-256-GCM y deriva la clave con scrypt, así que si alguien toca el archivo cifrado, el descifrado falla en vez de devolver basura.

Necesita Python 3 y el paquete `cryptography` (`pip install cryptography`; en Termux, `pkg install python-cryptography`).

## Uso

Cifrar. Pide la contraseña dos veces y crea `notas.txt.vault` al lado del original, que no se toca:

    python3 filevault.py lock notas.txt

Si además quieres borrar el original:

    python3 filevault.py lock notas.txt --delete-original

Descifrar. Escribe `notas.txt` y se niega a pisarlo si ya existe:

    python3 filevault.py unlock notas.txt.vault
    python3 filevault.py unlock notas.txt.vault --force

Para scripts, la contraseña se puede pasar por stdin (una sola línea):

    echo "mi clave" | python3 filevault.py unlock notas.txt.vault --password-stdin

Con contraseña incorrecta o archivo alterado sale un mensaje corto y código de salida 1. Los tests se lanzan con `python3 test_filevault.py`.

## Formato

El archivo `.vault` es esto, seguido sin separadores:

| bytes | contenido |
|-------|-----------|
| 4     | `FVLT` |
| 1     | versión (hoy, 1) |
| 16    | salt de scrypt, aleatorio en cada cifrado |
| 12    | nonce de GCM, aleatorio en cada cifrado |
| resto | texto cifrado + tag de autenticación de 16 bytes |

scrypt con N=2^15, r=8, p=1 saca la clave de 32 bytes. La cabecera no está autenticada aparte: si se cambia el salt o el nonce, la clave o el descifrado salen distintos y el tag no cuadra.

## Limitaciones

- Lee el archivo entero en memoria. Para ficheros de varios GB no sirve.
- No hay recuperación: si pierdes la contraseña, los datos se pierden.
- Los parámetros de scrypt están fijos en el código; no hay opción para cambiarlos.
- No oculta el tamaño del archivo ni que es un archivo filevault.
