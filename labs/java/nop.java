import java.io.*;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.zip.Adler32;

public class Main {

    public static void main(String[] args) {
        System.out.println("Memulai Phase 1...");
        processPhase1(); // Proses backup dan pengosongan instruksi
        System.out.println("Memulai Phase 2...");
        processPhase2(); // Proses perbaikan dan pengembalian instruksi asli
    }

    /**
     * Phase 1:
     * - Membaca file classes.dex
     * - Mencadangkan instruksi asli (code_item) ke backup.dat
     * - Mengosongkan instruksi di file DEX dan menyimpannya sebagai output.dex
     */
    public static void processPhase1() {
        String inputFile = "classes.dex";
        String outputFile = "output.dex";
        String backupFile = "backup.dat";
        try {
            // Baca seluruh isi file classes.dex ke dalam array byte
            byte[] dexBytes = Files.readAllBytes(Paths.get(inputFile));
            System.out.println("classes.dex berhasil dibaca. Ukuran: " + dexBytes.length + " bytes.");

            // Baca jumlah class_def_item dan offset ke class_def_item dari header DEX
            int classDefsSize = readInt(dexBytes, 0x60);
            int classDefsOffset = readInt(dexBytes, 0x64);
            System.out.println("Jumlah class_def_item: " + classDefsSize + ", offset: 0x" + Integer.toHexString(classDefsOffset));

            // Buka file backup untuk menulis data biner (cadangan code_item)
            DataOutputStream backupOut = new DataOutputStream(new FileOutputStream(backupFile));

            // Iterasi setiap class_def_item (setiap item berukuran 32 byte)
            for (int i = 0; i < classDefsSize; i++) {
                int classDefOffset = classDefsOffset + i * 32;
                int classDataOff = readInt(dexBytes, classDefOffset + 24);
                // Jika class memiliki data (code, field, method, dsb)
                if (classDataOff != 0) {
                    int currentOffset = classDataOff;
                    // Baca header class_data_item: static_fields_size, instance_fields_size, direct_methods_size, virtual_methods_size
                    ULEB128Result staticFieldsSize = readULEB128(dexBytes, currentOffset);
                    currentOffset += staticFieldsSize.length;
                    ULEB128Result instanceFieldsSize = readULEB128(dexBytes, currentOffset);
                    currentOffset += instanceFieldsSize.length;
                    ULEB128Result directMethodsSize = readULEB128(dexBytes, currentOffset);
                    currentOffset += directMethodsSize.length;
                    ULEB128Result virtualMethodsSize = readULEB128(dexBytes, currentOffset);
                    currentOffset += virtualMethodsSize.length;

                    // Lewati static_fields
                    for (int j = 0; j < staticFieldsSize.value; j++) {
                        ULEB128Result fieldIdxDiff = readULEB128(dexBytes, currentOffset);
                        currentOffset += fieldIdxDiff.length;
                        ULEB128Result accessFlags = readULEB128(dexBytes, currentOffset);
                        currentOffset += accessFlags.length;
                    }
                    // Lewati instance_fields
                    for (int j = 0; j < instanceFieldsSize.value; j++) {
                        ULEB128Result fieldIdxDiff = readULEB128(dexBytes, currentOffset);
                        currentOffset += fieldIdxDiff.length;
                        ULEB128Result accessFlags = readULEB128(dexBytes, currentOffset);
                        currentOffset += accessFlags.length;
                    }
                    // Proses direct_methods
                    for (int j = 0; j < directMethodsSize.value; j++) {
                        ULEB128Result methodIdxDiff = readULEB128(dexBytes, currentOffset);
                        currentOffset += methodIdxDiff.length;
                        ULEB128Result accessFlags = readULEB128(dexBytes, currentOffset);
                        currentOffset += accessFlags.length;
                        ULEB128Result codeOff = readULEB128(dexBytes, currentOffset);
                        currentOffset += codeOff.length;
                        // Jika method memiliki code_item (kode)
                        if (codeOff.value != 0) {
                            patchCodeItem(dexBytes, codeOff.value, backupOut);
                        }
                    }
                    // Proses virtual_methods
                    for (int j = 0; j < virtualMethodsSize.value; j++) {
                        ULEB128Result methodIdxDiff = readULEB128(dexBytes, currentOffset);
                        currentOffset += methodIdxDiff.length;
                        ULEB128Result accessFlags = readULEB128(dexBytes, currentOffset);
                        currentOffset += accessFlags.length;
                        ULEB128Result codeOff = readULEB128(dexBytes, currentOffset);
                        currentOffset += codeOff.length;
                        if (codeOff.value != 0) {
                            patchCodeItem(dexBytes, codeOff.value, backupOut);
                        }
                    }
                }
            }
            backupOut.close(); // Tutup file backup setelah semua code_item dibackup

            // Tulis ulang file output.dex dengan data dexBytes yang sudah termodifikasi (instruksi dihapus)
            Files.write(Paths.get(outputFile), dexBytes);
            System.out.println("Phase 1 selesai: output.dex dan backup.dat telah dibuat.");

            // Log sebagian isi file output.dex (misalnya 64 byte pertama)
            System.out.println("Isi awal output.dex (64 byte pertama): " + bytesToHex(sliceByteArray(dexBytes, 0, 64)));
        } catch(IOException e) {
            e.printStackTrace();
        }
    }

    /**
     * Phase 2:
     * - Membaca file output.dex dan backup.dat
     * - Mengembalikan instruksi asli ke posisi code_item di file DEX
     * - Memperbaiki header (signature dan checksum)
     * - Menyimpan file akhir sebagai repaired.dex
     */
    public static void processPhase2() {
        String inputFile = "output.dex";
        String outputFile = "repaired.dex";
        String backupFile = "backup.dat";
        try {
            // Baca file output.dex ke dalam array byte
            byte[] dexBytes = Files.readAllBytes(Paths.get(inputFile));
            System.out.println("output.dex berhasil dibaca. Ukuran: " + dexBytes.length + " bytes.");

            // Buka file backup untuk membaca data yang telah dicadangkan
            DataInputStream backupIn = new DataInputStream(new FileInputStream(backupFile));

            // Baca setiap entri backup: offset code_item, panjang instruksi, dan instruksi aslinya
            while (true) {
                try {
                    int codeOff = backupIn.readInt();
                    int insnLength = backupIn.readInt();
                    byte[] originalInstr = new byte[insnLength];
                    backupIn.readFully(originalInstr);
                    System.out.println("Mengembalikan code_item dari offset 0x" + Integer.toHexString(codeOff)
                            + " dengan panjang " + insnLength + " bytes.");
                    // Kembalikan instruksi asli ke posisi code_item
                    int insnsOffset = codeOff + 16; // header code_item berukuran 16 byte
                    if (insnsOffset + insnLength <= dexBytes.length) {
                        System.arraycopy(originalInstr, 0, dexBytes, insnsOffset, insnLength);
                    }
                } catch (EOFException e) {
                    // Ketika sudah mencapai akhir file backup, keluar dari loop
                    break;
                }
            }
            backupIn.close();
            // Perbaiki header DEX (signature dan checksum)
            resetDexCheckSum(dexBytes);
            Files.write(Paths.get(outputFile), dexBytes);
            System.out.println("Phase 2 selesai: repaired.dex telah dibuat.");

            // Log sebagian isi file repaired.dex (misalnya 64 byte pertama)
            System.out.println("Isi awal repaired.dex (64 byte pertama): " + bytesToHex(sliceByteArray(dexBytes, 0, 64)));
        } catch(IOException e) {
            e.printStackTrace();
        }
    }

    /**
     * Membaca integer 4 byte (little-endian) dari array data pada offset tertentu.
     */
    public static int readInt(byte[] data, int offset) {
        return (data[offset] & 0xFF) |
                ((data[offset+1] & 0xFF) << 8) |
                ((data[offset+2] & 0xFF) << 16) |
                ((data[offset+3] & 0xFF) << 24);
    }

    /**
     * Menulis integer 4 byte (little-endian) ke array data pada offset tertentu.
     */
    public static void writeInt(byte[] data, int offset, int value) {
        data[offset] = (byte)(value & 0xFF);
        data[offset+1] = (byte)((value >> 8) & 0xFF);
        data[offset+2] = (byte)((value >> 16) & 0xFF);
        data[offset+3] = (byte)((value >> 24) & 0xFF);
    }

    /**
     * Kelas pembantu untuk hasil pembacaan nilai ULEB128.
     */
    static class ULEB128Result {
        public int value;
        public int length;
    }

    /**
     * Membaca nilai ULEB128 dari array data pada offset tertentu.
     */
    public static ULEB128Result readULEB128(byte[] data, int offset) {
        ULEB128Result result = new ULEB128Result();
        int value = 0;
        int count = 0;
        int b;
        do {
            b = data[offset + count] & 0xFF;
            value |= (b & 0x7F) << (7 * count);
            count++;
        } while ((b & 0x80) != 0);
        result.value = value;
        result.length = count;
        return result;
    }

    /**
     * Fungsi patchCodeItem:
     * - Membaca header code_item di offset codeOff (header berukuran 16 byte)
     * - Mengambil nilai insns_size (4 byte di offset codeOff+12)
     * - Menghitung ukuran instruksi: insns_size * 2 (karena setiap instruksi 2 byte)
     * - Mencadangkan instruksi asli ke backupOut dan menampilkan log
     * - Mengosongkan instruksi (set menjadi 0) di array dexBytes
     */
    public static void patchCodeItem(byte[] dexBytes, int codeOff, DataOutputStream backupOut) {
        // Pastikan offset valid
        if (codeOff < 0 || codeOff + 16 > dexBytes.length) {
            return;
        }
        // Baca insns_size (jumlah 16-bit unit instruksi) dari header code_item
        int insnsSize = readInt(dexBytes, codeOff + 12);
        int insnsByteSize = insnsSize * 2; // Setiap instruksi 2 byte
        int insnsOffset = codeOff + 16;    // Instruksi dimulai setelah header 16 byte

        if (insnsOffset + insnsByteSize > dexBytes.length) {
            return;
        }
        // Backup instruksi asli ke array
        byte[] originalInstr = new byte[insnsByteSize];
        System.arraycopy(dexBytes, insnsOffset, originalInstr, 0, insnsByteSize);

        // Log isi code_item yang dibackup (dalam format hex)
        System.out.println("Backing up code_item di offset 0x" + Integer.toHexString(codeOff)
                + " dengan panjang " + insnsByteSize + " bytes. Isi: " + bytesToHex(originalInstr));

        try {
            // Tulis offset code_item dan panjang instruksi ke file backup
            backupOut.writeInt(codeOff);
            backupOut.writeInt(insnsByteSize);
            // Tulis instruksi aslinya
            backupOut.write(originalInstr);
        } catch(IOException e) {
            e.printStackTrace();
        }
        // Kosongkan instruksi pada array dexBytes dengan menyetel nilainya ke 0
        for (int i = insnsOffset; i < insnsOffset + insnsByteSize; i++) {
            dexBytes[i] = 0;
        }
    }

    /**
     * Memperbaiki header DEX dengan cara:
     * - Menghitung SHA-1 dari offset 32 hingga akhir file, lalu menyimpannya pada offset 12 (20 byte)
     * - Menghitung checksum Adler32 dari offset 12 hingga akhir file, lalu menyimpannya pada offset 8 (4 byte)
     */
    public static void resetDexCheckSum(byte[] dexBytes) {
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-1");
            // Perhitungkan SHA-1 dari seluruh file kecuali header awal 32 byte
            md.update(dexBytes, 32, dexBytes.length - 32);
            byte[] sha1 = md.digest();
            // Salin signature SHA-1 ke offset 12 (ukuran signature 20 byte)
            System.arraycopy(sha1, 0, dexBytes, 12, 20);
            System.out.println("Signature SHA-1 telah diperbarui: " + bytesToHex(sha1));
        } catch(NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
        Adler32 adler = new Adler32();
        // Hitung checksum dari offset 12 hingga akhir file
        adler.update(dexBytes, 12, dexBytes.length - 12);
        int checksum = (int) adler.getValue();
        // Tulis checksum ke offset 8
        writeInt(dexBytes, 8, checksum);
        System.out.println("Checksum Adler32 telah diperbarui: 0x" + Integer.toHexString(checksum));
    }

    /**
     * Fungsi utilitas untuk mengonversi byte array ke string dalam format hex.
     */
    public static String bytesToHex(byte[] bytes) {
        StringBuilder sb = new StringBuilder();
        for (byte b : bytes) {
            // Format setiap byte sebagai dua digit hex
            sb.append(String.format("%02X", b));
        }
        return sb.toString();
    }

    /**
     * Fungsi utilitas untuk mengambil sebagian dari array byte.
     */
    public static byte[] sliceByteArray(byte[] data, int start, int length) {
        byte[] slice = new byte[length];
        System.arraycopy(data, start, slice, 0, length);
        return slice;
    }
}
