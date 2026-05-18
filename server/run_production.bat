@echo off
echo Iniciando Servidor EDR en Modo Produccion...
echo La API estara disponible de forma publica en el puerto 8000
python -m uvicorn main:app --host 0.0.0.0 --port 8000
pause
