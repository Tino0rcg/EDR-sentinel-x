import os
import sys
import winreg as reg

def install_service():
    # 1. Obtener la ruta del ejecutable
    # Si estamos en el .py, buscamos el .exe en dist/
    # Si estamos en el .exe, usamos sys.executable
    if getattr(sys, 'frozen', False):
        exe_path = sys.executable
    else:
        cwd_exe = os.path.join(os.getcwd(), "SentinelAgent_V2.exe")
        dist_exe = os.path.join(os.getcwd(), "dist", "SentinelAgent.exe")
        if os.path.exists(cwd_exe):
            exe_path = cwd_exe
        elif os.path.exists(dist_exe):
            exe_path = dist_exe
        else:
            exe_path = os.path.join(os.getcwd(), "dist", "agent.exe")

    if not os.path.exists(exe_path):
        print(f"❌ Error: No se encontró el ejecutable en {exe_path}")
        print("Asegúrate de haber creado el .exe con PyInstaller primero.")
        return

    # 2. Registrar en el inicio de Windows (Registry)
    key_path = r"Software\Microsoft\Windows\CurrentVersion\Run"
    try:
        key = reg.OpenKey(reg.HKEY_CURRENT_USER, key_path, 0, reg.KEY_SET_VALUE)
        reg.SetValueEx(key, "SentinelAgent", 0, reg.REG_SZ, exe_path)
        reg.CloseKey(key)
        print("✅ Sentinel Agent registrado correctamente para iniciar con Windows.")
        print(f"Ruta registrada: {exe_path}")
        
        # 3. Iniciar el proceso ahora mismo
        os.startfile(exe_path)
        print("🚀 Agente iniciado en modo invisible.")
        
    except Exception as e:
        print(f"❌ Error al registrar el servicio: {e}")

if __name__ == "__main__":
    install_service()
