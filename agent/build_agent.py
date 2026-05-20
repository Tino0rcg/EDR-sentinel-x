import PyInstaller.__main__
import os
import shutil

print("--- Iniciando Compilación de Sentinel X EDR ---")

# Limpiar compilaciones previas si existen
if os.path.exists('build'):
    try:
        shutil.rmtree('build')
    except Exception as e:
        print(f"Aviso al limpiar build: {e}")

# Evitar borrar toda la carpeta dist si está bloqueada, solo intentar remover el exe anterior de V10
v10_exe = os.path.join('dist', 'SentinelAgent_V10.exe')
if os.path.exists(v10_exe):
    try:
        os.remove(v10_exe)
    except Exception as e:
        print(f"Aviso al eliminar v10_exe anterior: {e}")

print("Construyendo el archivo ejecutable silencioso...")

PyInstaller.__main__.run([
    'agent.py',
    '--onefile',
    '--noconsole',
    '--name=SentinelAgent_V10',
    '--clean'
])

print("--- Compilación Exitosa ---")
src = os.path.join('dist', 'SentinelAgent_V10.exe')
dst = 'SentinelAgent_V10.exe'
if os.path.exists(src):
    try:
        shutil.copy2(src, dst)
        print(f"Copiado a la raíz del agente: {dst}")
    except Exception as e:
        print(f"Error al copiar a la raíz: {e}")

