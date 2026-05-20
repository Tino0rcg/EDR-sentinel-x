import os
import sys
import winreg as reg
import subprocess

def install_service():
    # 1. Obtener la ruta del ejecutable
    # Si estamos en el .py, buscamos el .exe en dist/
    # Si estamos en el .exe, usamos sys.executable
    if getattr(sys, 'frozen', False):
        exe_path = sys.executable
    else:
        cwd_exe = os.path.join(os.getcwd(), "SentinelAgent_V10.exe")
        dist_exe = os.path.join(os.getcwd(), "dist", "SentinelAgent_V10.exe")
        if os.path.exists(cwd_exe):
            exe_path = cwd_exe
        elif os.path.exists(dist_exe):
            exe_path = dist_exe
        else:
            for v in range(9, 1, -1):
                path = os.path.join(os.getcwd(), f"SentinelAgent_V{v}.exe")
                if os.path.exists(path):
                    exe_path = path
                    break
            else:
                exe_path = os.path.join(os.getcwd(), "dist", "SentinelAgent.exe")

    if not os.path.exists(exe_path):
        print(f"❌ Error: No se encontró el ejecutable en {exe_path}")
        print("Asegúrate de haber creado el .exe con PyInstaller primero.")
        return

    # 2. Registrar inicio automático silencioso mediante Tarea Programada de Windows
    try:
        # Limpiar clave de registro antigua si existe
        try:
            key = reg.OpenKey(reg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\Run", 0, reg.KEY_SET_VALUE)
            reg.DeleteValue(key, "SentinelAgent")
            reg.CloseKey(key)
        except:
            pass
        
        # Crear tarea programada con los privilegios más altos (bypassea UAC en arranque)
        task_cmd = f'schtasks /create /tn "SentinelAgent" /tr "\\"{exe_path}\\"" /sc onlogon /rl highest /f'
        res = subprocess.run(task_cmd, shell=True, capture_output=True, text=True)
        if res.returncode != 0:
            raise Exception(res.stderr.strip())
            
        print("✅ Sentinel Agent registrado correctamente mediante Tarea Programada (UAC Bypass).")
        print(f"Ruta registrada: {exe_path}")
        
        # 3. Iniciar el proceso ahora mismo
        os.startfile(exe_path)
        print("🚀 Agente iniciado en modo invisible.")
        
    except Exception as e:
        print(f"❌ Error al registrar el servicio: {e}")

if __name__ == "__main__":
    install_service()
