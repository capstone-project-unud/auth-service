# Layanan Autentikasi

Repositori ini memuat layanan autentikasi Sistem Layanan Capstone Project Program Studi Teknologi Informasi, Universitas Udayana. Layanan dikembangkan menggunakan Go Fiber v3 dan PostgreSQL untuk mengelola kredensial serta sesi pengguna secara terpisah dari data profil akademik.

## Tanggung Jawab Layanan

Layanan menangani pemeriksaan email dan kata sandi, penerbitan sesi, logout, perubahan kata sandi, serta pencabutan sesi. Pembuatan kredensial dan pengaturan ulang kata sandi oleh administrator dilakukan melalui komunikasi internal dengan [layanan pengguna](https://github.com/capstone-project-unud/user-service).

Saat login, layanan meminta identitas dan status akun terkini dari layanan pengguna. Kredensial dihubungkan dengan UUID pengguna sehingga perubahan email tidak memerlukan pemindahan data kredensial.

## Penyimpanan dan Sesi

Database `auth-service` menggunakan skema `auth_service` dengan tabel `credentials` dan `sessions`. Kata sandi disimpan menggunakan bcrypt dengan faktor biaya 12. Kata sandi baru dibatasi antara 12 dan 72 byte sesuai batas algoritma yang digunakan.

Token sesi dibuat dari 32 byte acak dan disimpan sebagai hash SHA-256. Browser menerima cookie `capstone_session` dengan atribut `HttpOnly`, `SameSite=Strict`, dan masa berlaku absolut delapan jam. Logout mencabut sesi terkait; perubahan atau pengaturan ulang kata sandi mencabut seluruh sesi pengguna.

## Antarmuka API

| Metode | Endpoint | Fungsi |
| --- | --- | --- |
| POST | `/api/v1/auth/login` | Memeriksa kredensial dan membuat sesi |
| POST | `/api/v1/auth/logout` | Mengakhiri sesi |
| PUT | `/api/v1/auth/password` | Mengubah kata sandi pengguna aktif |

Endpoint `/internal/*` melayani verifikasi sesi dan pengelolaan kredensial antar layanan dengan `AUTH_INTERNAL_TOKEN`. Endpoint tersebut tidak diteruskan oleh API gateway.

## Struktur dan Konfigurasi

`cmd/api` memuat titik masuk aplikasi, `internal/config` memuat konfigurasi, `internal/httpapi` menangani permintaan HTTP, `internal/store` mengakses database, dan `migrations` menyimpan perubahan skema.

Layanan memerlukan Go 1.26 atau lebih baru. Konfigurasi tersedia pada `.env.example`, meliputi koneksi PostgreSQL, alamat layanan pengguna, dan token internal. Penyiapan database dikelola melalui repositori [infrastructure](https://github.com/capstone-project-unud/infrastructure).

```sh
go run ./cmd/api
go test ./...
```

Alamat lokal menggunakan port 8081. Pada lingkungan HTTPS, `COOKIE_SECURE` ditetapkan menjadi `true`. Berkas `.env` dan hasil kompilasi tidak disertakan dalam repositori.
