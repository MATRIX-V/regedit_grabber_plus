import tkinter as tk
from tkinter import messagebox, filedialog
import csv
import winreg

#---------------------------------------------------------------
#Elaborado por MatrixV04
#DONACIONES:
#BTC:1LXD2kzCJA5eSRRAjKPeVq664tPnB4Jorr
#USDT (TRC20):TLv4a7ukpdmJdXLDRgFTeEq3fQJyLfjg19
#---------------------------------------------------------------

# Diccionario de hives
hives = {
    "HKEY_LOCAL_MACHINE": winreg.HKEY_LOCAL_MACHINE,
    "HKEY_CURRENT_USER": winreg.HKEY_CURRENT_USER,
    "HKEY_CLASSES_ROOT": winreg.HKEY_CLASSES_ROOT,
    "HKEY_USERS": winreg.HKEY_USERS,
    "HKEY_CURRENT_CONFIG": winreg.HKEY_CURRENT_CONFIG
}

# Función principal
def procesar_archivo():
    # Seleccionar archivo .txt
    ruta_txt = filedialog.askopenfilename(
        filetypes=[("Archivos de texto", "*.txt")],
        title="Selecciona el archivo .txt con claves de registro"
    )

    if not ruta_txt:
        return  # Cancelado

    resultados = []

    try:
        with open(ruta_txt, "r", encoding="utf-8") as archivo:
            lineas = archivo.readlines()

        for linea in lineas:
            ruta_completa = linea.strip()
            if not ruta_completa:
                continue

            try:
                partes = ruta_completa.split("\\", 1)
                hive_str, subkey_path = partes[0], partes[1]

                hive = hives.get(hive_str.upper())
                if hive is None:
                    raise ValueError("Hive no reconocido.")

                key_parts = subkey_path.rsplit("\\", 1)
                key_path = key_parts[0]
                value_name = key_parts[1]

                with winreg.OpenKey(hive, key_path, 0, winreg.KEY_READ) as key:
                    try:
                        value, tipo = winreg.QueryValueEx(key, value_name)
                        resultado = ("\\\\".join([hive_str, key_path]), value_name, "Existe", str(value))
                    except FileNotFoundError:
                        resultado = ("\\\\".join([hive_str, key_path]), value_name, "No existe", "")
            except Exception as e:
                resultado = (ruta_completa, "", "Error", str(e))

            resultados.append(resultado)

    except Exception as e:
        messagebox.showerror("Error", f"No se pudo leer el archivo .txt:\n{e}")
        return

    # Guardar como CSV
    archivo_csv = filedialog.asksaveasfilename(defaultextension=".csv",
                                               filetypes=[("Archivos CSV", "*.csv")],
                                               title="Guardar resultado como...",
                                               initialfile="resultado_registro.csv")
    if not archivo_csv:
        return

    try:
        with open(archivo_csv, mode="w", newline="", encoding="utf-8") as archivo:
            writer = csv.writer(archivo)
            writer.writerow(["Ruta del Registro", "Clave", "Existe", "Valor"])
            writer.writerows(resultados)
        messagebox.showinfo("Éxito", f"Resultados exportados a:\n{archivo_csv}")
    except Exception as e:
        messagebox.showerror("Error", f"No se pudo guardar el archivo CSV:\n{e}")

# Interfaz
ventana = tk.Tk()
ventana.title("Verificador de Claves de Registro desde TXT")
ventana.configure(bg="#013220")
ventana.geometry("600x150")

etiqueta = tk.Label(ventana, text="Selecciona un archivo .txt con rutas de claves de registro:", bg="#013220", fg="white")
etiqueta.pack(pady=15)

boton_cargar = tk.Button(ventana, text="Seleccionar Archivo y Verificar", command=procesar_archivo, bg="white", fg="black")
boton_cargar.pack(pady=10)

ventana.mainloop()
