#!/bin/bash

# Pobierz domenę od użytkownika
echo "Podaj domenę:"
read domena
echo ""
valid_answer=0
while [[ $valid_answer -eq 0 ]]; do
    echo "Czy chcesz zapisać wyniki w bieżącym katalogu? (t/n)"
    read answer
    echo ""
    if [[ $answer == "t" ]]; then
        main_folder="./wyniki_osint_$domena"
        valid_answer=1
        elif [[ $answer == "n" ]]; then
        echo "Podaj ścieżkę do folderu, w którym chcesz zapisać wyniki:"
        read -e main_folder
        main_folder="$main_folder/wyniki_osint_$domena"
        valid_answer=1
        echo ""
    else
        echo "Niepoprawna odpowiedź. Proszę wybierz 't' lub 'n'."
        echo ""
    fi
done

echo "Wybrano folder: $(realpath $main_folder)"
echo ""

INTELX_API_KEY=""
shodan init  > /dev/null

# Tablica z nazwami folderów
declare -a folders=("wyniki_whois" "wyniki_theHarvester" "wyniki_crtsh" "wyniki_amass" "wyniki_dig" "wyniki_dnsrecon" "wyniki_waybackurls" "wyniki_intelx" "wyniki_shodan" "wyniki_eyewitness")

# Sprawdzenie i tworzenie folderów
[ ! -d "$main_folder" ] && mkdir "$main_folder"

for folder in "${folders[@]}"; do
    [ ! -d "$main_folder/$folder" ] && mkdir "$main_folder/$folder"
done

# Funkcja do zapisywania wyników
save_results() {
    local filename="$1"
    local command="$2"
    echo "Data i godzina: $(date +"%Y-%m-%d %H:%M:%S")" > "$filename"
    echo "Użyta komenda: $command" >> "$filename"
    echo "--------------------------------------------" >> "$filename"
    eval "$command"  >> "$filename"
    echo "Wynik ${3:-command} zapisano w pliku $filename"
}

# WHOIS
save_results "$main_folder/wyniki_whois/whois_$domena.txt" "whois $domena" "whois"

# theHarvester
save_results "$main_folder/wyniki_theHarvester/harvester_$domena.txt" "theHarvester -d $domena -b all" "theHarvester"

# crt.sh
save_results "$main_folder/wyniki_crtsh/crtsh_$domena.json" "curl -s \"https://crt.sh/?q=%25.$domena&output=json\" | jq ." "crt.sh"

# Amass
save_results "$main_folder/wyniki_amass/amass_$domena.txt" "amass enum -d $domena -passive" "Amass"

# dig
dig_results_file="$main_folder/wyniki_dig/dig_$domena.txt"
for type in A AAAA CNAME MX NS SOA TXT SRV
do
    echo "dig $domena $type" >> "$dig_results_file"
    dig $domena $type >> "$dig_results_file"
    echo "--------------------------------------------" >> "$dig_results_file"
done
echo "Wynik dig zapisano w pliku $dig_results_file"
# dnsrecon
save_results "$main_folder/wyniki_dnsrecon/dnsrecon_$domena.txt" "sudo dnsrecon -d $domena" "dnsrecon"

# waybackurls
save_results "$main_folder/wyniki_waybackurls/waybackurls_$domena.txt" "waybackurls -dates $domena" "waybackurls"

# intelx
save_results "$main_folder/wyniki_intelx/intelx_$domena.txt" "intelx.py -search $domena -apikey $INTELX_API_KEY" "intelx.io"

# Shodan
save_results "$main_folder/wyniki_shodan/shodan_$domena.txt" "shodan domain $domena" "Shodan"

# EyeWitness
eyewitness_dir="$main_folder/wyniki_eyewitness/eyewitness_$domena"
if [ -d "$eyewitness_dir" ]; then
    rm -rf "$eyewitness_dir"
fi
eyewitness_file="$main_folder/wyniki_eyewitness/eyewitness_$domena.txt"
sed '1,3d' "$main_folder/wyniki_amass/amass_$domena.txt" > temp_amass.txt
save_results "$eyewitness_file" "yes n | eyewitness -f temp_amass.txt --web -d $eyewitness_dir 2>/dev/null" "eyewitness"
rm temp_amass.txt

#################################################################################################################################
#Unikalna lista domen
#################################################################################################################################

declare -a domeny=()

# Wczytaj domeny z wyników Amass
mapfile -t -s 3 domeny_from_amass < "$main_folder/wyniki_amass/amass_$domena.txt"

# Wczytaj unikalne domeny z wyników crt.sh
declare -a domeny_from_crt=()
while read -r line; do
    domeny_from_crt+=("$line")
done < <(tail -n +4 "$main_folder/wyniki_crtsh/crtsh_$domena.json" | jq -r '.[].name_value' | sort | uniq)

# Wczytaj domeny z wyników theHarvester
declare -a domeny_from_theharvester=()

while IFS= read -r line; do
    domeny_from_theharvester+=("$line")
done < <(awk '/^\[\*\] Hosts found: [0-9]+/{flag=1;next} /^$/{flag=0} flag' "$main_folder/wyniki_theHarvester/harvester_$domena.txt")

# Połącz wszystkie tablice w jedną
domeny=("${domeny_from_amass[@]}" "---" "${domeny_from_crt[@]}" "---" "${domeny_from_theharvester[@]}")

# Filtruj domeny, które zaczynają się od "*."
filtered_domeny=()
for a in "${domeny[@]}"; do
    if [[ ! $a == \*.* ]]; then
        filtered_domeny+=("$a")
    fi
done

# Usunięcie duplikatów
declare -a unique_domeny=($(printf "%s\n" "${filtered_domeny[@]}" | sort -u))

declare -a cleaned_domeny=()

for j in "${unique_domeny[@]}"; do
    # Sprawdź, czy domena zawiera kropkę i nie zawiera spacji
    if [[ $j == *.* && ! $j == *" "* ]]; then
        cleaned_domeny+=("$j")
    fi
done

#################################################################################################################################
#Tłumaczenie domen nslookup oraz wypisanie otwartych portów za pomocą shodana
#################################################################################################################################
csv_file="$main_folder/wyniki_nslookup.csv"

# Utwórz plik CSV i dodaj nagłówki
echo "Domena,Adres IP,Otwarte porty" > "$csv_file"

for c in "${cleaned_domeny[@]}"; do
    # Używaj timeout dla nslookup i ustaw go na np. 5 sekund
    mapfile -t ips < <(timeout 5 nslookup "$c" 2>/dev/null | awk '/^Address: / { print $2 }')
    
    # Jeśli nie znaleziono żadnych adresów IP dla danej domeny
    if [[ ${#ips[@]} -eq 0 ]]; then
        echo "$c,,nie znaleziono informacji na temat tej domeny" >> "$csv_file"
    else
        for ip in "${ips[@]}"; do
            # Sprawdzanie otwartych portów przy użyciu Shodan
            shodan_result=$(shodan host "$ip" 2>/dev/null)
            ports_string=$(shodan host "$ip" 2>/dev/null | grep -Eo '[0-9]+/tcp|[0-9]+/udp' | awk -F"/" '{print $1}' | paste -sd " " -)
            
            # Jeśli nie znaleziono otwartych portów, ustaw wartość na "Brak"
            [[ -z $ports_string ]] && ports_string="Brak"
            
            # Dodaj domenę, jej adres IP oraz otwarte porty do pliku CSV
            echo "$c,$ip,$ports_string" >> "$csv_file"
        done
    fi
done
echo "Wynik nslookup zapisano w pliku $main_folder/wyniki_nslookup.csv"

#################################################################################################################################
#Raport
#################################################################################################################################

plik_raport="$main_folder/raport_$domena.txt"
plik_whois="$main_folder/wyniki_whois/whois_$domena.txt"
plik_harvester="$main_folder/wyniki_theHarvester/harvester_$domena.txt"
plik_amass="$main_folder/wyniki_amass/amass_$domena.txt"
plik_dnsrecon="$main_folder/wyniki_dnsrecon/dnsrecon_$domena.txt"
plik_crtsh="$main_folder/wyniki_crtsh/crtsh_$domena.json"

# Plik raportu
plik_raport="$main_folder/raport_$domena.txt"

# Funkcja do generowania raportu
function generuj_raport() {
    echo "Raport OSINT dla domeny: $domena" > "$plik_raport"
    echo "--------------------------------------------" >> "$plik_raport"
    echo "Data i godzina generowania raportu: $(date +"%Y-%m-%d %H:%M:%S")" >> "$plik_raport"
    echo "--------------------------------------------" >> "$plik_raport"
    
    # Sekcja WHOIS
    echo "Sekcja WHOIS" >> "$plik_raport"
    sed -n '1,/WHOIS database responses/p' "$plik_whois" | sed '$d' >> "$plik_raport"
    
    #Sekcja eyewitness
    eyewitness_dir="$main_folder/wyniki_eyewitness/eyewitness_$domena"
    # Sprawdzenie ilości screenów w katalogu
    liczba_screenow=$(find "$eyewitness_dir/screens" -type f -name '*.png' | wc -l)
    
    # Wypisanie adresów, które zostały zescreenowane
    adresy_zescreenowane=$(find "$eyewitness_dir/screens" -type f -name '*.png' | sed -e 's/^.*screens\///' -e 's/.png$//')

    echo "Sekcja eyewitness" >> "$plik_raport"
    echo "--------------------------------------------" >> "$plik_raport"
    echo "Liczba zescreenowanych adresów: $liczba_screenow" >> "$plik_raport"
    echo "Adresy, które zostały zescreenowane:" >> "$plik_raport"
    echo "$adresy_zescreenowane" >> "$plik_raport"

    # Sekcja waybackurls
    echo "" >> "$plik_raport"
    echo "Sekcja waybackurls" >> "$plik_raport"
    echo "--------------------------------------------" >> "$plik_raport"

    # Liczenie i wyświetlanie liczby znalezionych URL-i

    liczba_waybackurls=$(cat "$main_folder/wyniki_waybackurls/waybackurls_$domena.txt" | wc -l)
    echo "Liczba znalezionych URL-i przez waybackurls: $liczba_waybackurls" >> "$plik_raport"
    echo "" >> "$plik_raport"

    # Sekcja theHarvester
    echo "Sekcja theHarvester" >> "$plik_raport"
    echo "--------------------------------------------" >> "$plik_raport"
    echo "Data i godzina: $(date +"%Y-%m-%d %H:%M:%S")" >> "$plik_raport"
    echo "Użyta komenda: theHarvester -d $domena -b all" >> "$plik_raport"
    echo "" >> "$plik_raport"
    
    # Wyszukiwanie ASNS
    echo "Znalezione ASNS:" >> "$plik_raport"
    awk '/^\[\*\] ASNS found: [0-9]+/{flag=1;next} /^$/{flag=0} flag' "$plik_harvester" >> "$plik_raport"
    echo "" >> "$plik_raport"
    
    # Wyszukiwanie adresów URL
    echo "Znalezione adresy URL:" >> "$plik_raport"
    awk '/\[\*\] Interesting Urls found: [0-9]+/{flag=1;next} /^$/{flag=0} flag' "$plik_harvester" >> "$plik_raport"
    echo "" >> "$plik_raport"
    
    # Wyszukiwanie linków na Linkedin
    echo "Znalezione linki na Linkedin:" >> "$plik_raport"
    awk '/\[\*\] LinkedIn Links found: [0-9]+/ {flag=1; next} /^$/ {flag=0} flag' "$plik_harvester" >> "$plik_raport"
    echo "" >> "$plik_raport"
    
    # Wyszukiwanie adresów IP
    echo "Znalezione adresy IP:" >> "$plik_raport"
    awk '/\[\*\] IPs found: [0-9]+/ {flag=1; next} /^$/ {flag=0} flag' "$plik_harvester" >> "$plik_raport"
    echo "" >> "$plik_raport"
    
    # Wyszukiwanie adresów email
    echo "Znalezione adresy email:" >> "$plik_raport"
    awk '/\[\*\] Emails found: [0-9]+/ {flag=1; next} /^$/ {flag=0} flag' "$plik_harvester" >> "$plik_raport"
    echo "" >> "$plik_raport"
      
    # Lista znalezionych domen
    echo "Lista znalezionych domen" >> "$plik_raport"
    echo "--------------------------------------------" >> "$plik_raport"
    for z in "${cleaned_domeny[@]}"; do
       echo "$z" >> "$plik_raport"
    done
    echo "--------------------------------------------" >> "$plik_raport"
 
    # Sekcja DIG
    echo "" >> "$plik_raport"
    echo "Sekcja DIG" >> "$plik_raport"
    echo "--------------------------------------------" >> "$plik_raport"
    echo "Data i godzina: $(date +"%Y-%m-%d %H:%M:%S")" >> "$plik_raport"
    echo "Użyte komendy: dig $domena $type" >> "$plik_raport"
    echo "--------------------------------------------" >> "$plik_raport"
    
    for type in A AAAA CNAME MX NS SOA TXT SRV
    do
        echo "Rekordy $type dla domeny $domena:" >> "$plik_raport"
        dig +short $domena $type | sed 's/^/    /' >> "$plik_raport"
        echo "" >> "$plik_raport"
    done
    
    # Sekcja DNSrecon
    echo "" >> "$plik_raport"
    echo "Sekcja DNSrecon" >> "$plik_raport"
    echo "--------------------------------------------" >> "$plik_raport"
    cat $plik_dnsrecon >> "$plik_raport"
    
    # Sekcja crt.sh
    
    # Pobranie aktualnej daty w formacie ISO 8601
    aktualna_data=$(date -u +"%Y-%m-%dT%H:%M:%S")
    
    # Inicjalizacja pliku raportowego
    echo "" >> "$plik_raport"
    echo "Wygasłe certyfikaty - crt.sh:" >> "$plik_raport"
    echo "--------------------------------------------" >> "$plik_raport"
    
    # Pomiń wstępne linie w pliku JSON
    json_content=$(awk '/\[/{flag=1} flag' "$plik_crtsh")
    
    # Analiza certyfikatów w treści JSON
    echo "$json_content" | jq -c '.[] | select(.not_after < "'$aktualna_data'")' | while read -r wygasly_certyfikat; do
        common_name=$(echo "$wygasly_certyfikat" | jq -r '.common_name')
        not_after=$(echo "$wygasly_certyfikat" | jq -r '.not_after')
        echo "Wygasły certyfikat: $common_name, ważny do: $not_after" >> "$plik_raport"
    done

    # Sekcja intelx
    echo "" >> "$plik_raport"
    echo "Sekcja intelx.io" >> "$plik_raport"
    echo "--------------------------------------------" >> "$plik_raport"
    echo "Data i godzina: $(date +"%Y-%m-%d %H:%M:%S")" >> "$plik_raport"
    echo "Użyta komenda: intelx.py -search $domena -apikey "Klucz API"" >> "$plik_raport"
    echo "--------------------------------------------" >> "$plik_raport"
    echo "Wyciekłe dane uwierzytelniające: " >> "$plik_raport"
    echo "" >> "$plik_raport"
    # Filtrowanie wyników i dodawanie do raportu
    grep '^[^ ]*:[^ ]*$' "$main_folder/wyniki_intelx/intelx_$domena.txt" >> "$plik_raport"
    echo "--------------------------------------------" >> "$plik_raport"
    echo "Raport zapisano w pliku $main_folder/raport_$domena.txt"
}
generuj_raport
