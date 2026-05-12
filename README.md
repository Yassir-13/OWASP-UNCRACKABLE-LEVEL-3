================================================================================
                  WRITE-UP : OWASP UNCRACKABLE LEVEL 3 (MASTG)
================================================================================

Auteur     : [Ton nom]
Date       : 12 mai 2026
Cible      : UnCrackable-Level3.apk (OWASP MASTG)
Plateforme : Windows + Android Studio Emulator
Outils     : apktool, jadx, Ghidra, apksigner, zipalign, adb, Python

================================================================================
                              TABLE DES MATIERES
================================================================================

1. Objectif du challenge
2. Reconnaissance initiale
3. Analyse statique du code Java (JADX)
4. Decompilation et patching Smali (apktool)
5. Rebuild, signature et installation de l'APK patche
6. Analyse de la bibliotheque native (Ghidra)
7. Extraction et decodage de la cle secrete (XOR)
8. Validation finale
9. Conclusion et lecons apprises


================================================================================
                          LISTE DES CAPTURES D'ECRAN
================================================================================

  [SCR-01] Screenshot_2026-05-12_212244.png  -> Decompilation apktool
  [SCR-02] Screenshot_2026-05-12_212252.png  -> JADX : analyse de verifyLibs()
  [SCR-03] 1778621079685_image.png           -> Hex dump de libfoo.so (ELF)
  [SCR-04] Screenshot_2026-05-12_214001.png  -> Rebuild apktool
  [SCR-05] Screenshot_2026-05-12_220806.png  -> App patchee : ecran de saisie
  [SCR-06] Screenshot_2026-05-12_221908.png  -> Ghidra : pseudo-code FUN_001012c0
  [SCR-07] Screenshot_2026-05-12_222010.png  -> Script xor.py (VS Code)
  [SCR-08] Screenshot_2026-05-12_222032.png  -> Execution Python : cle trouvee
  [SCR-09] Screenshot_2026-05-12_222104.png  -> Validation : "Success!"


================================================================================
1. OBJECTIF DU CHALLENGE
================================================================================

UnCrackable Level 3 est le troisieme et dernier challenge de la serie OWASP
MASTG (Mobile Application Security Testing Guide). Il combine plusieurs
mecanismes de protection :

  - Detection de root (checkRoot1/2/3)
  - Detection de debugger (isDebuggable)
  - Verification d'integrite via CRC sur classes.dex et libfoo.so
  - Logique de verification du secret deplacee dans une bibliotheque native (JNI)
  - Obfuscation du code natif (boucle LCG + malloc + liste chainee)
  - Stockage de la cle sous forme XOR-encodee

L'objectif est de retrouver la chaine secrete attendue par l'application sans
modifier la logique de verification.


================================================================================
2. RECONNAISSANCE INITIALE
================================================================================

Telechargement de l'APK depuis le repository officiel OWASP MASTG.

Verification du contenu (`unzip -l UnCrackable-Level3.apk`) :
  - classes.dex
  - lib/armeabi-v7a/libfoo.so
  - lib/arm64-v8a/libfoo.so
  - lib/x86/libfoo.so
  - lib/x86_64/libfoo.so
  - AndroidManifest.xml
  - resources.arsc

Package         : sg.vantagepoint.uncrackable3
Activite princ. : sg.vantagepoint.uncrackable3.MainActivity

[VOIR SCR-03 : 1778621079685_image.png]
   --> Hex dump confirmant que libfoo.so est bien un binaire ELF 64-bit
       (signature 7F 45 4C 46 = ".ELF").


================================================================================
3. ANALYSE STATIQUE DU CODE JAVA (JADX)
================================================================================

[VOIR SCR-02 : Screenshot_2026-05-12_212252.png]
   --> Vue JADX-GUI de la methode verifyLibs() dans MainActivity.

Structure du package observee :

  sg.vantagepoint.uncrackable3
    |-- MainActivity     (UI + detections + chargement natif)
    |-- CodeCheck        (appelle check_code natif)
    |-- BuildConfig
    |-- R

  sg.vantagepoint.util
    |-- RootDetection    (checkRoot1, checkRoot2, checkRoot3)
    |-- IntegrityCheck   (isDebuggable)

Points cles dans MainActivity (visibles sur SCR-02) :

  a) System.loadLibrary("foo")     -> charge libfoo.so au demarrage
  b) verifyLibs()                  -> calcule le CRC de chaque libfoo.so et
                                      de classes.dex. Si != CRC attendu, met
                                      le flag "tampered" a 31337 (0x7a69).
                                      Visible lignes 50-69 dans SCR-02.
  c) Dans onCreate(), un bloc combine :
        - checkRoot1/2/3()
        - isDebuggable()
        - tampered != 0
     Si l'une de ces conditions est vraie -> showDialog("Rooting or tampering
     detected.") puis exit.
  d) init(byte[] xorkey)           -> appelle la fonction native init avec la
                                      cle "pizzapizzapizzapizzapizz" (24 octets)
  e) verify() -> appelle CodeCheck.check_code(input) qui delegue au natif.

Observation cle : la logique de comparaison finale n'est PAS en Java. Elle est
deleguee a la fonction native check_code dans libfoo.so.


================================================================================
4. DECOMPILATION ET PATCHING SMALI (APKTOOL)
================================================================================

4.1 Decompilation
-----------------
  > java -jar apktool_3.0.1.jar d UnCrackable-Level3.apk -o C:\apktool\uncrackable3

[VOIR SCR-01 : Screenshot_2026-05-12_212244.png]
   --> Sortie de la commande apktool d : baksmaling, decoding resources,
       copying lib, etc.

4.2 Identification du bloc a neutraliser
-----------------------------------------
Dans smali/sg/vantagepoint/uncrackable3/MainActivity.smali, methode onCreate(),
le bloc suivant doit etre court-circuite :

    invoke-static {}, Lsg/vantagepoint/util/RootDetection;->checkRoot1()Z
    move-result v0
    if-nez v0, :cond_0
    ...
    sget v0, Lsg/vantagepoint/uncrackable3/MainActivity;->tampered:I
    if-eqz v0, :cond_1

    :cond_0
    const-string v0, "Rooting or tampering detected."
    invoke-direct {p0, v0}, Lsg/vantagepoint/uncrackable3/MainActivity;->showDialog(...)V

    :cond_1
    new-instance v0, Lsg/vantagepoint/uncrackable3/CodeCheck;

4.3 Patch applique
-------------------
Ajout d'un saut inconditionnel "goto :cond_1" juste avant le bloc de
verifications. Cela bypass d'un coup toutes les detections (root, debug,
tampering) :

    invoke-virtual {v0, v1}, Lsg/.../MainActivity$2;->execute(...)Landroid/os/AsyncTask;

    goto :cond_1     # <-- PATCH AJOUTE

    invoke-static {}, Lsg/vantagepoint/util/RootDetection;->checkRoot1()Z
    ... (reste inchange, mais devient code mort) ...

    :cond_1
    new-instance v0, Lsg/vantagepoint/uncrackable3/CodeCheck;


================================================================================
5. REBUILD, SIGNATURE ET INSTALLATION DE L'APK PATCHE
================================================================================

5.1 Rebuild
-----------
  > java -jar apktool_3.0.1.jar b C:\apktool\uncrackable3 ^
      -o C:\Users\PC\apktool\UnCrackable-Level3-patched.apk

[VOIR SCR-04 : Screenshot_2026-05-12_214001.png]
   --> Sortie apktool b : smaling, building resources, building apk file,
       importing lib. Build reussi.

5.2 Creation d'un keystore (mot de passe de l'ancien oublie)
-------------------------------------------------------------
  > "C:\Program Files\Java\jdk-23\bin\keytool.exe" -genkey -v ^
      -keystore my-key.keystore ^
      -alias mykey -keyalg RSA -keysize 2048 -validity 10000 ^
      -storepass android -keypass android ^
      -dname "CN=Test, OU=Test, O=Test, L=Test, S=Test, C=US"

5.3 Alignement
--------------
  > zipalign -p -f -v 4 UnCrackable-Level3-patched.apk UnCrackable-Level3-aligned.apk

5.4 Signature
-------------
  > apksigner sign --ks my-key.keystore ^
      --ks-pass pass:android --key-pass pass:android ^
      --ks-key-alias mykey ^
      --out UnCrackable-Level3-signed.apk ^
      UnCrackable-Level3-aligned.apk

5.5 Installation
----------------
  > adb uninstall sg.vantagepoint.uncrackable3
  > adb install UnCrackable-Level3-signed.apk

[VOIR SCR-05 : Screenshot_2026-05-12_220806.png]
   --> L'application patchee demarre sans declencher la boite "Rooting or
       tampering detected" et affiche directement l'ecran "Enter the Secret
       String". Patch valide.


================================================================================
6. ANALYSE DE LA BIBLIOTHEQUE NATIVE (GHIDRA)
================================================================================

6.1 Extraction de libfoo.so
----------------------------
ABI cible (emulateur x86_64) :
  > adb shell getprop ro.product.cpu.abi
  -> x86_64

Fichier analyse : lib/x86_64/libfoo.so

6.2 Import dans Ghidra
-----------------------
  - New Project -> Import File -> libfoo.so
  - Format : ELF
  - Analyse automatique (toutes les options par defaut)

6.3 Localisation de la fonction cible
--------------------------------------
Symbol Tree -> Exports -> recherche "check_1code"

Fonction trouvee :
  Java_sg_vantagepoint_uncrackable3_CodeCheck_check_1code

Celle-ci appelle a son tour la fonction interne :
  FUN_001012c0   (nom auto-genere par Ghidra)

6.4 Analyse du pseudo-code de FUN_001012c0
-------------------------------------------
[VOIR SCR-06 : Screenshot_2026-05-12_221908.png]
   --> Pseudo-code decompile par Ghidra montrant la fin de la fonction.

Structure observee :
  - Une boucle LCG (Linear Congruential Generator) qui s'execute ~80 fois,
    avec une constante multiplicative 0x33333. But : creer du bruit pour
    compliquer l'analyse statique.
  - L'allocation d'une liste chainee via malloc (_1_sub_doit__opaque_list1_*).
  - A la toute fin, les vraies donnees utiles sont ecrites dans le buffer
    "param_1" (passe par check_code).

Code utile a la fin de la fonction (capture SCR-06) :

    if (_1_sub_doit__opaque_list1_1 != (uint *)0x0) {
        *(undefined8 *)((long)param_1 + 9)  = 0;
        *(undefined8 *)((long)param_1 + 0x11) = 0;
        *param_1    = 0;
        param_1[1]  = 0;
        *param_1    = 0x1549170f1311081d;
        param_1[1]  = 0x15131d5a1903000d;
        param_1[2]  = 0x14130817005a0e08;
    }
    return;

==> Ces 3 quadwords (24 octets au total) constituent la cle XOR-encodee qui
    sera comparee a l'entree utilisateur (apres traitement avec la cle
    "pizzapizzapizzapizzapizz").


================================================================================
7. EXTRACTION ET DECODAGE DE LA CLE SECRETE (XOR)
================================================================================

7.1 Conversion little-endian
-----------------------------
Les valeurs etant stockees en little-endian sur x86_64, on inverse l'ordre des
octets de chaque quadword :

  0x1549170f1311081d  ->  1d 08 11 13 0f 17 49 15
  0x15131d5a1903000d  ->  0d 00 03 19 5a 1d 13 15
  0x14130817005a0e08  ->  08 0e 5a 00 17 08 13 14

Concatenation (24 octets) :
  1d 08 11 13 0f 17 49 15 0d 00 03 19 5a 1d 13 15 08 0e 5a 00 17 08 13 14

7.2 Script Python de decodage
------------------------------
[VOIR SCR-07 : Screenshot_2026-05-12_222010.png]
   --> Code source du script xor.py dans VS Code (5 lignes).

Fichier : xor.py

    encoded = bytes.fromhex("1d0811130f1749150d0003195a1d1315080e5a0017081314")
    xor_key = b"pizzapizzapizzapizzapizza"   # 24 octets

    secret = bytes(a ^ b for a, b in zip(encoded, xor_key))
    print("Cle secrete trouvee :", secret.decode())

7.3 Execution
--------------
  > cd Desktop
  > python xor.py
  Cle secrete trouvee : making owasp great again

[VOIR SCR-08 : Screenshot_2026-05-12_222032.png]
   --> Sortie CMD confirmant le decodage : "making owasp great again".


================================================================================
8. VALIDATION FINALE
================================================================================

8.1 Saisie dans l'application
------------------------------
  - Ouverture de UnCrackable Level 3 (version patchee)
  - Saisie dans le champ : making owasp great again
  - Clic sur VERIFY

8.2 Resultat
-------------
[VOIR SCR-09 : Screenshot_2026-05-12_222104.png]
   --> Capture finale montrant la boite de dialogue :

  +--------------------------------------+
  |  Success!                            |
  |  This is the correct secret.         |
  |                                      |
  |                            [ OK ]    |
  +--------------------------------------+

CHALLENGE RESOLU.


9. CONCLUSION ET LECONS APPRISES

9.1 Resume de la chaine d'attaque
-----------------------------------
  1. Decompilation Java -> identification des protections superficielles.
  2. Patch Smali -> neutralisation des detections (root/debug/tampering).
  3. Rebuild + signature -> APK fonctionnel avec protections desactivees.
  4. Analyse native (Ghidra) -> reperage de la cle XOR-encodee dans libfoo.so.
  5. Decodage Python -> recuperation du secret en clair.

9.3 Role des composants identifies
------------------------------------
  - check_code()    : point d'entree JNI. Recoit la chaine utilisateur,
                      la transforme et la compare au buffer cible.
  - FUN_001012c0    : initialise le buffer de reference avec la cle XOR-encodee
                      apres une grosse couche d'obfuscation.
  - tampered (Java) : flag positionne par verifyLibs() si un CRC ne correspond
                      pas. Lu dans onCreate() pour fermer l'app si != 0.
  - libfoo.so       : porte la logique secrete et la cle obfusquee.

9.4 Pourquoi le buffer final est cle du challenge
---------------------------------------------------
Toute la logique de verification se reduit, in fine, a un memcmp entre :
  - input XOR "pizzapizzapizzapizzapizz"
  - constante en dur dans libfoo.so

Recuperer la constante revient donc a inverser l'unique operation reelle. Le
reste du code natif (obfuscation, listes chainees, LCG) n'a pas d'incidence
sur le resultat et peut etre ignore une fois la fin de la fonction reperee.
