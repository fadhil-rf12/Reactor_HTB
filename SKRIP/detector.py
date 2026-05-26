#!/usr/bin/env python3
import requests
import urllib3
import sys

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

def probe_server_actions(target_url):
    """
    Melakukan probing aktif terhadap perilaku penanganan Server Actions Next.js.
    """
    base_url = target_url.rstrip('/')
    print(f"[*] Melakukan uji perilaku terhadap: {base_url}")
    
    # 1. Menargetkan endpoint utama tempat Server Actions biasanya dieksekusi
    # Next.js memproses tindakan server langsung pada rute halaman terkait
    test_endpoints = [
        "/",
        "/login",
        "/api",
    ]
    
    # Header Next-Action biasanya berupa hash string (SHA) sepanjang 40 karakter.
    # Kita berikan hash tiruan untuk melihat bagaimana server menangani deserialisasi ID aksi tersebut.
    fake_action_id = "d8f34a2c1b0e9f8a7c6b5d4e3f2a1b0c9d8e7f6a"
    
    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) HTB-Hunter",
        "Next-Action": fake_action_id,
        "Content-Type": "text/plain;charset=UTF-8",
        "Accept": "text/x-component",
        "RSC": "1"
    }
    
    # Payload tiruan format Flight RSC yang rusak
    # Format Flight asli biasanya menggunakan pola "1:I[...]" atau "0:[...]"
    malformed_rsc_payload = '0:{"action":"execute","params":[]}\n'

    for endpoint in test_endpoints:
        url = base_url + endpoint
        print(f"[*] Mengirim probe ke endpoint: {endpoint}")
        
        try:
            # Server Actions harus dikirim via POST
            response = requests.post(url, headers=headers, data=malformed_rsc_payload, verify=False, timeout=8)
            
            # Analisis tanda-tanda penanganan internal Next.js RSC
            server_header = response.headers.get("Server", "").lower()
            content_type = response.headers.get("Content-Type", "").lower()
            
            # Indikator 1: Header respons mengembalikan tipe komponen khusus Next.js
            if "text/x-component" in content_type:
                print(f"[+] KONDISI TERDETEKSI: Server merespons dengan format RSC 'text/x-component'.")
                print(f"[!] Server mengonfirmasi adanya arsitektur Next.js App Router aktif di endpoint ini.")
                
                # Indikator 2: Pengecekan pesan error spesifik dari engine React/Next.js
                if "invalid" in response.text.lower() or "action" in response.text.lower() or response.status_code == 500:
                    print("[WARN] Respons mengembalikan kode 500 atau pesan error pemrosesan.")
                    print("[!] Skenario HTB: Target kemungkinan besar rentan terhadap eksploitasi deserialisasi jika patch belum diterapkan.")
                return True
                
            # Indikator 3: Jika server membuang respons kosong atau memutus koneksi secara tidak wajar saat membaca stream RSC
            elif response.status_code == 400 and ("bad request" in response.text.lower() or "action" in response.text.lower()):
                print(f"[+] Deteksi Perilaku: Server menolak payload RSC secara eksplisit (Status 400).")
                print("[*] Layanan Next.js terindikasi mengenali struktur kendali internal ini.")
                return True

        except requests.exceptions.RequestException as e:
            print(f"[-] Gagal mengirim probe ke {endpoint}: {e}")
            
    print("[-] Tidak ada respons spesifik RSC/Server Actions yang terdeteksi dari endpoint yang diuji.")
    return False

def main():
    if len(sys.argv) < 2:
        print("Penggunaan: python3 nextjs_behavior_check.py <URL_Target>")
        print("Contoh:    python3 nextjs_behavior_check.py http://10.10.11.234:3000")
        sys.exit(1)
        
    target = sys.argv[1]
    print("=== Next.js RSC / Server Actions Behavioral Prober ===")
    probe_server_actions(target)
    print("=== Selesai ===")

if __name__ == "__main__":
    main()
