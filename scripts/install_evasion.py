# scripts/install_evasion.py
import subprocess
import sys

def install_playwright():

    print("🔧 تثبيت متطلبات التخفي...")
    
    subprocess.run([sys.executable, "-m", "pip", "install", "playwright"])
    
    print("📥 تنزيل المتصفحات...")
    subprocess.run([sys.executable, "-m", "playwright", "install", "chromium"])
    subprocess.run([sys.executable, "-m", "playwright", "install", "firefox"])
    subprocess.run([sys.executable, "-m", "playwright", "install", "webkit"])
    
    print("✅ تم التثبيت بنجاح!")

if __name__ == "__main__":
    install_playwright()
