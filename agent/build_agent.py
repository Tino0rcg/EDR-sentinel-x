import PyInstaller.__main__
import os
import shutil

print("--- Iniciando Compilación de Sentinel X EDR ---")

# Limpiar compilaciones previas si existen
if os.path.exists('build'):
    shutil.rmtree('build')
if os.path.exists('dist'):
    shutil.rmtree('dist')

print("Construyendo el archivo ejecutable silencioso...")

PyInstaller.__main__.run([
    'agent.py',
    '--onefile',
    '--noconsole',
    '--name=SentinelAgent',
    '--clean'
])

print("--- Compilación Exitosa ---")
print("Tu instalador cliente está listo en la carpeta: dist/SentinelAgent.exe")
