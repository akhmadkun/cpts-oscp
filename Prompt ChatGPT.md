# URL Documentation to Anki

```
Saya akan memberikan URL dokumentasi resmi Cisco ACI.

URL:
https://www.cisco.com/c/en/us/td/docs/dcn/aci/apic/6x/aci-fundamentals/cisco-aci-fundamentals-61x/fundamentals-61x.html

Tugasmu adalah mempelajari seluruh isi dokumentasi pada URL tersebut, termasuk subbagian yang relevan pada halaman yang sama. Gunakan dokumentasi Cisco resmi sebagai sumber utama. Jangan hanya mengandalkan ringkasan hasil pencarian.

Tujuan pembelajaran:
Saya adalah network engineer berpengalaman dan telah memiliki hands-on Cisco ACI. Saya menggunakan materi ini untuk memperdalam teori, memahami design behavior, melakukan troubleshooting kasus sulit, dan mempersiapkan project kompleks. Karena itu, jangan terlalu banyak membahas langkah konfigurasi dasar kecuali konfigurasi tersebut menjelaskan perilaku sistem atau design implication.

Kerjakan dalam dua bagian berikut.

BAGIAN 1 — PENJELASAN MATERI

Jelaskan ulang isi dokumentasi dalam bahasa Indonesia secara terstruktur dan mudah dipahami, tetapi pertahankan istilah teknis Cisco ACI dalam bahasa Inggris.

Untuk setiap topik penting, jelaskan:

1. Apa fungsi dan tujuan konsep tersebut.
2. Bagaimana cara kerjanya di dalam ACI.
3. Komponen atau managed object yang terlibat.
4. Packet flow atau control-plane behavior jika relevan.
5. Hubungannya dengan Tenant, VRF, BD, EPG, ESG, Contract, L3Out, Leaf, Spine, dan APIC jika relevan.
6. Design consideration dan trade-off.
7. Default behavior dan hal yang berubah ketika fitur diaktifkan.
8. Requirement, limitation, dependency, dan scalability consideration.
9. Failure scenario serta dampaknya terhadap forwarding.
10. Cara melakukan verification dan troubleshooting.
11. Kesalahan konfigurasi atau miskonsepsi yang sering terjadi.
12. Contoh skenario implementasi di project nyata.

Jangan hanya menerjemahkan dokumentasi. Jelaskan hubungan sebab-akibat dan alasan di balik setiap behavior.

Jika dokumentasi berisi tabel, diagram, warning, note, recommendation, limitation, atau exception, jangan dilewatkan. Jelaskan mengapa informasi tersebut penting.

Bedakan dengan jelas antara:

- fakta eksplisit dari dokumentasi;
- penjelasan atau inferensi teknis;
- recommendation atau best practice;
- behavior yang bergantung pada versi APIC/NX-OS.

Jika ada informasi yang tidak dapat dipastikan dari dokumentasi, katakan secara jelas dan jangan mengarang.

BAGIAN 2 — FLASHCARDS

Setelah penjelasan selesai, ubah poin-poin paling penting menjadi flashcard berbahasa Inggris.

Prioritaskan flashcard tentang:

- core concepts;
- internal behavior;
- packet forwarding;
- control-plane behavior;
- design decisions;
- comparison between similar features;
- default behavior;
- dependencies and limitations;
- failure scenarios;
- troubleshooting logic;
- verification methods;
- common misconceptions;
- project-relevant edge cases.

Jangan membuat kartu dari detail administratif yang tidak penting, langkah GUI sederhana, atau fakta yang terlalu mudah ditebak.

ATURAN FLASHCARD

1. Gunakan tiga kolom:
   question | answer | brief explanation

2. Gunakan tanda "|" hanya sebagai pemisah kolom.
   Jangan menambahkan "|" pada awal atau akhir baris.

3. Jangan membuat header tabel.

4. Letakkan seluruh flashcard di dalam satu code block agar siap diimpor atau diedit.

5. Setiap flashcard harus atomic: satu kartu hanya menguji satu fakta, konsep, behavior, atau keputusan.

6. Question harus memiliki konteks Cisco ACI yang jelas sehingga tidak ambigu ketika dicampur dengan flashcard dari topik lain.

7. Answer harus singkat dan hanya berisi satu key fact, concept, term, state, atau behavior.

8. Brief explanation harus menjelaskan alasan atau mekanismenya secara ringkas, bukan hanya mengulang jawaban.

9. Gunakan simple and direct English.

10. Jangan membuat pertanyaan yes/no jika dapat diubah menjadi pertanyaan konseptual.

11. Hindari pertanyaan yang hanya menguji hafalan nomor halaman, lokasi menu GUI, atau urutan klik.

12. Jangan membuat flashcard berdasarkan soal dump atau mengasumsikan jawaban tertentu hanya karena terlihat seperti soal ujian.

KEYWORD FORMATTING

Setiap kolom harus memiliki minimal satu keyword berwarna.

Question dan brief explanation harus memiliki minimal dua keyword berwarna.

Gunakan warna secara bergantian:

<span style="color:blue">keyword</span>
<span style="color:darkred">keyword</span>

Contoh format:

In <span style="color:blue">Cisco ACI</span>, where is a <span style="color:darkred">remote endpoint</span> stored for fabric-wide lookup?|<span style="color:blue">COOP database</span>|The <span style="color:darkred">spine proxy</span> uses the <span style="color:blue">COOP database</span> to locate endpoints learned on remote leaf switches.

QUALITY CONTROL

Sebelum memberikan hasil, lakukan pemeriksaan berikut:

- Apakah semua konsep penting dari dokumentasi sudah tercakup?
- Apakah warning, limitation, exception, dan default behavior sudah dibahas?
- Apakah setiap jawaban flashcard hanya mengandung satu konsep utama?
- Apakah pertanyaannya tetap jelas ketika dicampur dengan topik lain?
- Apakah explanation menjelaskan “why” atau “how”?
- Apakah ada kartu duplikat atau terlalu mirip?
- Apakah ada klaim yang tidak didukung dokumentasi?
- Apakah format setiap baris tepat tiga kolom?
- Apakah tidak ada tanda "|" tambahan di awal atau akhir baris?

Di bagian akhir, cantumkan:

- judul dan versi dokumentasi;
- URL sumber;
- tanggal akses;
- jumlah flashcard;
- topik penting yang tidak dibahas karena berada di luar cakupan halaman.

Jika dokumentasinya panjang, kerjakan per chapter atau logical section. Jangan mengurangi kedalaman pembahasan hanya agar seluruh dokumentasi selesai dalam satu jawaban. Hentikan pada batas bagian yang logis, sebutkan bagian terakhir yang telah selesai, lalu tunggu instruksi “lanjutkan”.
```

# URL Documentation to PPT

```
Saya akan memberikan sebuah URL dokumentasi resmi Cisco ACI.

URL dokumentasi:  
[MASUKKAN URL DI SINI]

Tugasmu adalah membaca dan memahami seluruh isi dokumentasi tersebut, lalu mengubah poin-poin pentingnya menjadi presentasi PowerPoint yang interaktif, visual, terstruktur, dan mudah dipahami oleh pemula.

## 1. Tujuan presentasi

Presentasi ditujukan untuk peserta yang:

- memiliki pengetahuan dasar traditional networking;
    
- memahami VLAN, subnet, routing, switching, dan firewall secara umum;
    
- belum memahami Cisco ACI atau baru mulai mempelajarinya;
    
- perlu memahami konsep, hubungan antarobjek, traffic flow, dan alasan penggunaan suatu fitur;
    
- tidak membutuhkan seluruh detail konfigurasi CLI atau GUI pada tahap awal.
    

Presentasi harus membantu peserta menjawab:

1. Apa masalah yang diselesaikan oleh konsep atau fitur ini?
    
2. Mengapa fitur tersebut diperlukan di Cisco ACI?
    
3. Bagaimana cara kerjanya?
    
4. Komponen ACI apa saja yang terlibat?
    
5. Bagaimana traffic atau policy diproses?
    
6. Apa contoh penggunaannya dalam project nyata?
    
7. Apa yang dapat terjadi jika konfigurasinya salah?
    

Jangan sekadar menerjemahkan atau memindahkan isi dokumentasi ke slide.

## 2. Penggunaan sumber

Gunakan URL Cisco yang diberikan sebagai sumber utama.

Lakukan hal berikut:

- baca seluruh bagian yang relevan pada halaman;
    
- periksa diagram, tabel, note, warning, limitation, prerequisite, dan recommendation;
    
- ikuti subhalaman hanya jika diperlukan untuk menjelaskan konsep utama;
    
- identifikasi versi APIC atau ACI yang berlaku;
    
- jangan mengarang behavior yang tidak dijelaskan oleh dokumentasi;
    
- bedakan fakta dokumentasi, penyederhanaan untuk pemula, dan technical inference;
    
- cantumkan URL sumber pada slide referensi;
    
- cantumkan sumber singkat pada slide yang memiliki klaim penting atau version-specific behavior.
    

Jika ada perbedaan behavior berdasarkan versi ACI, jelaskan secara singkat dan sebutkan versinya.

## 3. Tahap analisis sebelum membuat slide

Sebelum membuat PowerPoint, lakukan analisis internal untuk mengidentifikasi:

- tujuan utama dokumentasi;
    
- konsep fundamental;
    
- terminologi baru;
    
- hubungan antarobjek ACI;
    
- dependency dan prerequisite;
    
- packet flow atau control-plane flow;
    
- default behavior;
    
- design consideration;
    
- limitation dan caveat;
    
- common misconception;
    
- failure scenario;
    
- contoh implementasi yang relevan.
    

Kelompokkan informasi tersebut menjadi alur pembelajaran yang logis. Jangan mengikuti urutan dokumentasi secara kaku jika urutannya kurang cocok untuk peserta pemula.

## 4. Pendekatan penjelasan

Gunakan pola berikut untuk setiap konsep utama:

1. **Masalah**  
    Jelaskan masalah jaringan yang ingin diselesaikan.
    
2. **Analogi**  
    Gunakan analogi sederhana jika membantu, tetapi jangan sampai mengubah arti teknis.
    
3. **Konsep ACI**  
    Perkenalkan fitur dan istilah Cisco ACI yang relevan.
    
4. **Cara kerja**  
    Jelaskan proses atau mekanismenya secara bertahap.
    
5. **Visualisasi**  
    Gunakan diagram untuk menunjukkan hubungan objek, packet flow, policy flow, atau perubahan state.
    
6. **Contoh project**  
    Berikan contoh sederhana dari lingkungan data center.
    
7. **Kesalahan umum**  
    Jelaskan miskonsepsi atau konfigurasi yang sering menyebabkan masalah.
    
8. **Verification**  
    Berikan cara sederhana untuk memverifikasi behavior jika relevan.
    

Gunakan bahasa Indonesia yang sederhana. Pertahankan istilah teknis Cisco ACI dalam bahasa Inggris, misalnya:

- Tenant
    
- VRF
    
- Bridge Domain
    
- EPG
    
- ESG
    
- Contract
    
- Application Profile
    
- L3Out
    
- Leaf
    
- Spine
    
- APIC
    
- Endpoint
    
- COOP
    
- Policy CAM
    
- Service Graph
    
- Policy-Based Redirect
    

Jelaskan istilah tersebut ketika pertama kali muncul.

## 5. Struktur PowerPoint

Susun presentasi menggunakan struktur berikut. Sesuaikan jumlah slide dengan kompleksitas materi.

### Bagian pembuka

1. Title slide
    
2. Learning objectives
    
3. Prerequisite knowledge
    
4. Agenda
    
5. Gambaran masalah pada traditional network
    
6. Posisi topik dalam arsitektur Cisco ACI
    

### Bagian konsep

Untuk setiap konsep utama, gunakan beberapa slide yang mencakup:

- konsep dalam satu kalimat;
    
- fungsi dan tujuan;
    
- komponen yang terlibat;
    
- hubungan dengan objek ACI lainnya;
    
- cara kerja bertahap;
    
- packet flow atau policy flow;
    
- contoh penggunaan;
    
- design consideration;
    
- common mistake;
    
- verification atau troubleshooting dasar.
    

### Bagian penutup

- rangkuman konsep utama;
    
- tabel istilah penting;
    
- common misconceptions;
    
- mini case study;
    
- knowledge check;
    
- jawaban dan pembahasan;
    
- key takeaways;
    
- recommended next topic;
    
- references.
    

## 6. Aturan isi setiap slide

Terapkan aturan berikut:

- satu slide membahas satu gagasan utama;
    
- gunakan judul yang menyampaikan kesimpulan, bukan hanya nama topik;
    
- maksimal 3–5 bullet utama per slide;
    
- gunakan kalimat pendek;
    
- hindari paragraf panjang;
    
- hindari menyalin teks dokumentasi secara verbatim;
    
- tampilkan hanya informasi yang perlu dilihat peserta;
    
- pindahkan detail penjelasan presenter ke speaker notes;
    
- jelaskan singkatan saat pertama kali digunakan;
    
- gunakan contoh alamat IP, VLAN, VRF, EPG, dan subnet yang konsisten pada seluruh presentasi;
    
- gunakan progressive disclosure untuk proses yang memiliki beberapa tahap;
    
- pecah diagram yang kompleks menjadi beberapa slide;
    
- jangan mengecilkan font agar semua informasi masuk dalam satu slide.
    

Setiap slide harus memiliki salah satu fungsi berikut:

- memperkenalkan masalah;
    
- menjelaskan konsep;
    
- menunjukkan hubungan;
    
- menunjukkan urutan proses;
    
- membandingkan pilihan;
    
- memberikan contoh;
    
- menguji pemahaman;
    
- merangkum materi.
    

Jika sebuah slide tidak menjalankan salah satu fungsi tersebut, pertimbangkan untuk menghapusnya.

## 7. Aturan visualisasi

Utamakan visual dibanding teks panjang.

Gunakan:

- topology diagram untuk hubungan perangkat;
    
- hierarchy diagram untuk hubungan objek;
    
- flow diagram untuk packet flow atau policy flow;
    
- before-and-after diagram untuk menunjukkan perubahan;
    
- comparison table untuk membandingkan fitur;
    
- callout untuk warning dan limitation;
    
- timeline atau numbered steps untuk menjelaskan urutan proses;
    
- icon sederhana untuk server, endpoint, APIC, leaf, spine, router, firewall, dan cloud.
    

Untuk setiap diagram:

- tampilkan maksimal informasi yang diperlukan;
    
- gunakan label yang jelas;
    
- gunakan panah dengan arah yang benar;
    
- bedakan data plane, control plane, dan policy relationship menggunakan warna atau jenis garis;
    
- gunakan contoh yang konsisten;
    
- hindari diagram dekoratif yang tidak menambah pemahaman;
    
- pastikan diagram tetap dapat dipahami tanpa penjelasan verbal yang panjang.
    

Jangan menggunakan AI-generated network diagrams jika akurasi teknisnya tidak dapat dijamin. Buat diagram menggunakan PowerPoint shapes, connectors, icons, dan text labels agar dapat diedit.

Jika menggunakan diagram dari dokumentasi Cisco:

- jangan menyalinnya tanpa konteks;
    
- sederhanakan atau gambar ulang jika diperlukan;
    
- pertahankan arti teknis;
    
- cantumkan sumber.
    

## 8. Desain presentasi

Gunakan spesifikasi berikut:

- aspect ratio 16:9;
    
- desain modern dan profesional;
    
- gaya visual data center/networking;
    
- latar belakang terang atau gelap dengan kontras tinggi;
    
- warna utama biru Cisco, putih, abu-abu, dan satu warna aksen;
    
- font yang mudah dibaca;
    
- ukuran judul minimal 28 pt;
    
- ukuran isi minimal 18 pt;
    
- layout dan posisi elemen konsisten;
    
- gunakan whitespace yang cukup;
    
- hindari animasi berlebihan;
    
- hindari slide yang terlalu padat;
    
- hindari gambar yang hanya berfungsi sebagai dekorasi.
    

Gunakan color coding secara konsisten, misalnya:

- biru: policy atau control-plane;
    
- hijau: permitted traffic;
    
- merah: denied traffic atau failure;
    
- oranye: warning atau design consideration;
    
- abu-abu: supporting infrastructure.
    

Tambahkan legend jika warna memiliki arti teknis.

## 9. Elemen interaktif

Tambahkan interaktivitas yang tetap kompatibel saat PowerPoint dijalankan di komputer lain.

Gunakan:

- clickable table of contents;
    
- tombol Home, Previous, dan Next;
    
- section divider;
    
- pertanyaan prediksi sebelum suatu konsep dijelaskan;
    
- “What do you think happens next?”;
    
- knowledge-check slide;
    
- mini quiz dengan pilihan jawaban;
    
- answer-reveal menggunakan slide berikutnya;
    
- before-and-after scenario;
    
- click-through packet walk;
    
- mini troubleshooting case;
    
- summary checkpoint pada akhir setiap bagian.
    

Jangan bergantung pada macro, external plugin, atau fitur interaktif yang mudah rusak.

Untuk quiz, gunakan dua slide:

1. slide pertanyaan;
    
2. slide jawaban dan pembahasan.
    

Buat minimal:

- 3 concept-check questions;
    
- 2 scenario-based questions;
    
- 1 troubleshooting question.
    

Pertanyaan harus menguji pemahaman konsep, bukan hafalan istilah semata.

## 10. Speaker notes

Tambahkan speaker notes pada setiap slide yang membutuhkan penjelasan.

Speaker notes harus mencakup:

- tujuan slide;
    
- cara menjelaskan slide;
    
- analogi yang dapat digunakan;
    
- detail teknis yang sengaja tidak ditampilkan;
    
- pertanyaan yang dapat diajukan kepada peserta;
    
- transisi menuju slide berikutnya;
    
- warning jika ada penyederhanaan konsep.
    

Speaker notes tidak boleh hanya mengulang isi slide.

## 11. Contoh dan case study

Gunakan satu skenario project yang konsisten pada seluruh presentasi, misalnya:

- dua kelompok server: Web dan Application;
    
- satu VRF;
    
- beberapa Bridge Domain;
    
- beberapa EPG;
    
- komunikasi antar-EPG menggunakan Contract;
    
- koneksi external network melalui L3Out;
    
- firewall atau service insertion jika relevan.
    

Berikan nama objek yang mudah dibaca, misalnya:

- Tenant: `Production`
    
- VRF: `PROD-VRF`
    
- Bridge Domain: `WEB-BD`
    
- EPG: `WEB-EPG`
    
- Contract: `WEB-TO-APP`
    
- L3Out: `PROD-L3OUT`
    

Jangan menambahkan objek yang tidak relevan dengan materi.

## 12. Kedalaman teknis

Materi ditujukan untuk pemula, tetapi harus tetap akurat.

Gunakan tiga tingkat informasi:

- **Must Know**: konsep utama yang wajib dipahami;
    
- **Good to Know**: detail yang membantu memahami behavior;
    
- **Advanced Note**: detail lanjutan yang tidak perlu dihafal pemula.
    

Jangan menghilangkan limitation atau behavior penting hanya karena targetnya pemula. Sederhanakan cara menjelaskannya, bukan faktanya.

## 13. Output yang harus dibuat

Buat file PowerPoint `.pptx` yang siap dipresentasikan dan masih dapat diedit.

Selain file PowerPoint, berikan ringkasan berikut:

1. judul presentasi;
    
2. target audience;
    
3. versi dokumentasi;
    
4. jumlah slide;
    
5. estimasi durasi presentasi;
    
6. daftar learning objectives;
    
7. struktur section;
    
8. daftar visual utama;
    
9. daftar quiz atau knowledge check;
    
10. URL sumber.
    

Jika lingkungan mendukung pembuatan file, jangan hanya memberikan outline atau isi slide dalam teks. Buat file `.pptx` yang sebenarnya.

Jika saya memberikan template PowerPoint, gunakan template tersebut dan pertahankan:

- slide master;
    
- theme;
    
- font;
    
- color palette;
    
- header dan footer;
    
- logo;
    
- style visual.
    

## 14. Quality control

Sebelum menyerahkan hasil, render dan periksa seluruh slide.

Pastikan:

- tidak ada teks terpotong;
    
- tidak ada objek saling menimpa;
    
- tidak ada font yang terlalu kecil;
    
- tidak ada diagram yang salah arah;
    
- label dan connector mudah dibaca;
    
- alignment dan spacing konsisten;
    
- seluruh hyperlink dan navigation button bekerja;
    
- speaker notes tersedia;
    
- terminology konsisten;
    
- contoh addressing konsisten;
    
- technical behavior sesuai sumber;
    
- quiz memiliki jawaban yang benar;
    
- setiap slide memberikan nilai pembelajaran;
    
- presentasi dapat dipahami oleh pemula tanpa membaca dokumentasi aslinya terlebih dahulu.
    

Jika dokumentasi terlalu panjang, jangan memadatkan seluruh isi ke dalam satu presentasi yang terlalu penuh. Bagi menjadi beberapa module PowerPoint berdasarkan logical section dan jelaskan pembagiannya sebelum membuat file.
```