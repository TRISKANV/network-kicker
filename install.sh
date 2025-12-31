#!/bin/bash

# --- Colores para una mejor visualización ---
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m' # No Color

# --- Función para imprimir mensajes ---
print_msg() {
    echo -e "${GREEN}[+]${NC} $1"
}

print_warn() {
    echo -e "${YELLOW}[!]${NC} $1"
}

print_error() {
    echo -e "${RED}[-]${NC} $1"
}

# --- Comprobar si se está ejecutando en Termux ---
if [ ! -d "/data/data/com.termux/files/home" ]; then
    print_error "Este script de instalación está diseñado exclusivamente para Termux."
    print_error "Por favor, usalo en un dispositivo Android con la app Termux."
    exit 1
fi

print_msg "Iniciando la instalación de Network Kicker para Termux..."

# --- 1. Actualizar paquetes de Termux ---
print_msg "Actualizando paquetes de Termux..."
pkg update -y && pkg upgrade -y
if [ $? -ne 0 ]; then
    print_error "Falló la actualización de paquetes. Revisa tu conexión a internet e intenta de nuevo."
    exit 1
fi

# --- 2. Instalar dependencias del sistema ---
print_msg "Instalando dependencias del sistema (python, git, libpcap)..."
pkg install -y python git libpcap
if [ $? -ne 0 ]; then
    print_error "Falló la instalación de dependencias."
    exit 1
fi

# --- 3. Clonar el repositorio desde GitHub ---
# PREGUNTAR AL USUARIO POR SU USUARIO DE GITHUB
echo
print_warn "Necesito tu nombre de usuario de GitHub para clonar el repositorio."
read -p "Ingresa tu nombre de usuario de GitHub: " GITHUB_USER

if [ -z "$GITHUB_USER" ]; then
    print_error "El nombre de usuario no puede estar vacío."
    exit 1
fi

REPO_URL="https://github.com/$GITHUB_USER/network-kicker.git"
PROJECT_DIR="network-kicker"

print_msg "Clonando el repositorio desde $REPO_URL..."

# Si el directorio ya existe, lo borramos para una instalación limpia
if [ -d "$HOME/$PROJECT_DIR" ]; then
    print_warn "El directorio '$PROJECT_DIR' ya existe. Será eliminado para una instalación limpia."
    rm -rf "$HOME/$PROJECT_DIR"
fi

git clone "$REPO_URL" "$HOME/$PROJECT_DIR"

if [ $? -ne 0 ]; then
    print_error "Falló la clonación del repositorio. Verificá que el nombre de usuario '$GITHUB_USER' y el repositorio 'network-kicker' sean correctos y públicos."
    exit 1
fi

cd "$HOME/$PROJECT_DIR" || exit 1

# --- 4. Instalar dependencias de Python ---
print_msg "Instalando la librería 'scapy' para Python..."
pip install scapy
if [ $? -ne 0 ]; then
    print_error "Falló la instalación de la librería scapy."
    exit 1
fi

# --- 5. Finalización y ejecución ---
echo
print_msg "¡Instalación completada con éxito!"
print_msg "El script principal está en: $HOME/$PROJECT_DIR/kick_off_network.py"

echo
print_warn "RECUERDA: Para que el script funcione, tu teléfono Android debe estar rooteado."
print_warn "El script necesita permisos de root (usando el comando 'tsu') para manipular paquetes de red."

echo
read -p "¿Querés ejecutar el script ahora? (s/N): " choice

if [[ "$choice" == "s" || "$choice" == "S" ]]; then
    print_msg "Ejecutando kick_off_network.py..."
    echo "Usá Ctrl+C para detener el ataque."
    echo
    tsu python kick_off_network.py
else
    print_msg "Para ejecutar el script manualmente más tarde, usá los siguientes comandos:"
    echo "cd $HOME/$PROJECT_DIR"
    echo "tsu python kick_off_network.py"
fi

exit 0