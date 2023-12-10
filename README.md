# Skrypt OSINT do analizy domen

## Opis
Ten skrypt bash służy do przeprowadzania analizy OSINT (Open Source Intelligence) na wybranej domenie. Zbiera dane z różnych źródeł takich jak whois, theHarvester, crt.sh, Amass, dig, dnsrecon, waybackurls, intelx.io, Shodan i EyeWitness, a następnie generuje szczegółowy raport.

## Wymagania
- System Linux z bash
- Narzędzia: whois, curl, jq, dig, nslookup, grep, awk, sed
- Zainstalowane i skonfigurowane: theHarvester, Amass, dnsrecon, waybackurls, intelx.py, EyeWitness, Shodan CLI
- Klucze API dla intelx.io i Shodan

## Konfiguracja Kluczy API
Aby skrypt działał poprawnie, konieczne jest ustawienie kluczy API dla intelx.io i Shodan. Ustaw swoje klucze API w poniższych liniach skryptu:
```bash
INTELX_API_KEY="Twój_Klucz_API_Intelx.io"
shodan init "Twój_Klucz_API_Shodan"
```
Znajdź te linie w skrypcie i zastąp puste ciągi tekstowe odpowiednimi kluczami API.

## Instalacja
1. Sklonuj repozytorium lub pobierz skrypt.
2. Nadaj skryptowi prawa do wykonania:
   ```bash
   chmod +x nazwa_skryptu.sh
   ```

## Użycie
1. Uruchom skrypt:
   ```bash
   ./nazwa_skryptu.sh
   ```
2. Podaj nazwę domeny, którą chcesz zbadać.
3. Wybierz, czy chcesz zapisać wyniki w bieżącym katalogu, czy podać ścieżkę do innego katalogu.
4. Czekaj na zakończenie przetwarzania i sprawdź wygenerowane raporty w wybranym katalogu.

## Struktura Wyjścia
Skrypt tworzy główny folder o nazwie `wyniki_osint_[domena]`, zawierający podfoldery dla każdego z narzędzi oraz plik raportu z końcową analizą.

## Uwagi
- Upewnij się, że wszystkie wymagane narzędzia są zainstalowane i skonfigurowane przed uruchomieniem skryptu.
- Używanie skryptu do celów nielegalnych jest zabronione.
