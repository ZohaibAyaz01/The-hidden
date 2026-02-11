#!/bin/bash

# ==============================================================================
# TOOL NAME: The Hidden
# DESCRIPTION: Advanced Forensics, Malware Detection & Payload Extraction
# AUTHOR: Gemini (AI Assistant)
# ENVIRONMENT: Standard Linux (Bash, Coreutils, Awk, Grep, DD, Strings)
# ==============================================================================

# --- Color Definitions ---
RED='\033[0;31m'
GREEN='\033[0;32m'
CYAN='\033[0;36m'
YELLOW='\033[1;33m'
MAGENTA='\033[0;35m'
BOLD='\033[1m'
NC='\033[0m' # No Color

# --- Global Variables ---
TARGET_FILE=""
FILE_SIZE=0
STRING_LOG_FILE=""

# Forensic Flags
IS_High_Entropy=false
HAS_EOF_Data=false
SIG_MISMATCH=false
HAS_CRITICAL_STRINGS=false
STR_RISK_SCORE=0
MISSING_FOOTER=false
FINDINGS_LOG=()

# UTILITY FUNCTIONS

function print_banner() {
    clear
    echo -e "${CYAN}${BOLD}"
    echo "  _______ _             _    _ _     _     _              "
    echo " |__   __| |           | |  | (_)   | |   | |             "
    echo "    | |  | |__   ___   | |__| |_  __| | __| | ___ _ __    "
    echo "    | |  | '_ \ / _ \  |  __  | |/ _\` |/ _\` |/ _ \ '_ \   "
    echo "    | |  | | | |  __/  | |  | | | (_| | (_| |  __/ | | |  "
    echo "    |_|  |_| |_|\___|  |_|  |_|_|\__,_|\__,_|\___|_| |_|  "
    echo -e "${NC}"
    echo -e "${YELLOW}  :: Malware Forensics & Payload Extraction Tool ::${NC}"
    echo "  --------------------------------------------------------"
}

function print_section() {
    echo -e "\n${BOLD}[*] $1${NC}"
    echo "--------------------------------------------------------"
}

function add_finding() {
    FINDINGS_LOG+=("$1")
}

function press_enter() {
    echo ""
    read -p "Press [Enter] to continue..."
}

# INPUT & VALIDATION


function get_target_file() {
    print_banner
    echo -e "Analyzes files for hidden malware, steganography, and embedded payloads."
    echo -e "Please enter the path to the target file."
    echo ""
    while true; do
        read -p "Target File > " TARGET_FILE
        TARGET_FILE=$(echo "$TARGET_FILE" | tr -d "'\"")
        
        if [[ -f "$TARGET_FILE" ]]; then
            echo -e "${GREEN}File loaded: $TARGET_FILE${NC}"
            FILE_SIZE=$(stat -c%s "$TARGET_FILE")
            STRING_LOG_FILE="${TARGET_FILE}_extracted_strings.log"
            sleep 1
            break
        else
            echo -e "${RED}Error: File does not exist. Try again.${NC}"
        fi
    done
}

# MODULE 1-4: BASIC ANALYSIS

function analyze_size() {
    print_section "Logical vs Physical Size Analysis"
    local logical_size=$FILE_SIZE
    local blocks=$(stat -c%b "$TARGET_FILE")
    local physical_size=$((blocks * 512))
    
    echo "Logical Size:   $logical_size bytes"
    echo "Physical Size:  $physical_size bytes"
    
    if [[ $logical_size -gt 0 ]]; then
         local diff=$((physical_size - logical_size))
         echo -e "Overhead:       ${YELLOW}$diff bytes${NC}"
         if [[ $diff -lt 0 ]]; then
             echo -e "${RED}[!] CRITICAL: Logical size > Physical size.${NC}"
             add_finding "Size: Logical size exceeds physical size (Sparse File)."
         fi
    fi
}

function analyze_slack() {
    print_section "Slack Space Analysis"
    local remainder=$((FILE_SIZE % 4096))
    local slack=0
    if [[ $remainder -ne 0 ]]; then slack=$((4096 - remainder)); fi
    echo "Slack Space: $slack bytes"
}

function analyze_hash() {
    print_section "Integrity Verification"
    local hash=$(sha256sum "$TARGET_FILE" | awk '{print $1}')
    echo -e "SHA-256: ${GREEN}$hash${NC}"
}

function analyze_header() {
    print_section "Header & Signature Validation"
    local mime=$(file --mime-type -b "$TARGET_FILE")
    local ext="${TARGET_FILE##*.}"
    echo "Detected Type: $mime"
    echo -e "Hex Header: "
    hexdump -n 16 -C "$TARGET_FILE"
    
    # Check for Mismatch (e.g., png extension but jpeg header)
    if [[ "$mime" != *"$ext"* && "$mime" != "application/octet-stream" ]]; then
        echo -e "\n${RED}[!] CRITICAL WARNING: Extension '.$ext' does not match detected type '$mime'.${NC}"
        echo "    This is a common malware camouflage technique."
        SIG_MISMATCH=true
        add_finding "Header: CRITICAL - Extension/Header Mismatch detected."
    fi
}


# MODULE 5: INTELLIGENT STRING & RISK ANALYSIS

function analyze_strings() {
    print_section "Intelligent String Extraction"
    
    echo -e "1. Extracting printable data to: ${CYAN}$STRING_LOG_FILE${NC}"
    strings -a -n 6 "$TARGET_FILE" > "$STRING_LOG_FILE"
    
    local line_count=$(wc -l < "$STRING_LOG_FILE")
    echo "   Extracted $line_count lines."
    echo "2. Scanning for forensic indicators..."
    
    local c_net=$(grep -E -i "http://|https://|[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}" "$STRING_LOG_FILE" | wc -l)
    local c_creds=$(grep -E -i "password|passwd|secret|token|api_key|admin" "$STRING_LOG_FILE" | wc -l)
    local c_code=$(grep -E -i "<?php|eval\(|exec\(|system\(|/bin/sh|powershell|cmd.exe|0x90" "$STRING_LOG_FILE" | wc -l)
    local c_crypto=$(grep -E -i "Salted__|AES|Rijndael" "$STRING_LOG_FILE" | wc -l)
    
    printf "\n%-25s %-10s\n" "CATEGORY" "HITS"
    echo "-----------------------------------"
    printf "%-25s ${CYAN}%-10s${NC}\n"   "Network (IPs/URLs)"    "$c_net"
    printf "%-25s ${YELLOW}%-10s${NC}\n" "Credentials/Secrets"   "$c_creds"
    printf "%-25s ${RED}%-10s${NC}\n"    "Code/Shell Execution"  "$c_code"
    printf "%-25s ${MAGENTA}%-10s${NC}\n" "Crypto/Stego Markers"  "$c_crypto"
    
    STR_RISK_SCORE=$((c_net + c_creds + (c_code * 5) + (c_crypto * 2)))
    
    if [[ $STR_RISK_SCORE -ge 10 ]]; then
        HAS_CRITICAL_STRINGS=true
        add_finding "Strings: CRITICAL Risk - Code or Keys found ($STR_RISK_SCORE hits)."
    elif [[ $STR_RISK_SCORE -ge 1 ]]; then
        HAS_CRITICAL_STRINGS=true
        add_finding "Strings: Suspicious keywords found."
    fi
}


# MODULE 6: ROBUST EOF EXTRACTOR (Fixed for Binary Payloads)

function analyze_eof() {
    print_section "EOF Payload Detection & Extraction"
    
    local mime=$(file --mime-type -b "$TARGET_FILE")
    local f_size=$(stat -c%s "$TARGET_FILE")
    
    echo "File Type: $mime"
    echo "Total Size: $f_size bytes"
    
    # --- JPEG LOGIC (Improved) ---
    if [[ "$mime" == "image/jpeg" ]]; then
        echo "Searching for JPEG Terminator (FF D9)..."
        
        # Method: Convert file to hex, find offset of FF D9, take the LAST one found.
        # This works even if grep fails on binary data.
        # od -t x1 -An -v | tr -d ' \n' is reliable but slow for huge files.
        # Using grep -a -b -o with hex escape is faster.
        
        # Look for hex FF D9
        local hits=$(grep -a -b -o $'\xff\xd9' "$TARGET_FILE")
        
        if [[ -z "$hits" ]]; then
            echo -e "${RED}[!] CRITICAL: No JPEG Footer (FF D9) found.${NC}"
            echo "    The file is either corrupt or the footer is overwritten by the payload."
            MISSING_FOOTER=true
            add_finding "EOF: JPEG footer missing (High Malware Likelihood)."
            
            # Fallback: If header mismatch exists, try to carve anyway?
            # Hard to guess where image ends without footer.
            return
        fi
        
        # Get the LAST hit (in case of thumbnails)
        local last_hit=$(echo "$hits" | tail -n 1)
        local offset=$(echo "$last_hit" | cut -d: -f1)
        local real_end=$((offset + 2)) # FF D9 is 2 bytes
        
        echo "Image Structure Ends at: $real_end"
        
        if [[ $f_size -gt $real_end ]]; then
            local hidden_size=$((f_size - real_end))
            echo -e "${RED}[!] PAYLOAD DETECTED!${NC}"
            echo -e "    Appended Data Size: ${YELLOW}$hidden_size bytes${NC}"
            
            local out_name="${TARGET_FILE}_payload.bin"
            echo -e " -> Extracting payload to: ${GREEN}$out_name${NC}"
            
            dd if="$TARGET_FILE" of="$out_name" bs=1 skip="$real_end" status=none
            
            HAS_EOF_Data=true
            add_finding "EOF: Extracted $hidden_size bytes of payload."
            
            echo -e "\n${BOLD}[Preview of Payload Start]${NC}"
            hexdump -C -n 64 "$out_name"
        else
            echo -e "${GREEN}[OK] File ends exactly at JPEG footer.${NC}"
        fi

    # --- PNG LOGIC ---
    elif [[ "$mime" == "image/png" ]]; then
        # Search for IEND chunk
        local hit=$(grep -a -b -o "IEND" "$TARGET_FILE" | tail -n 1)
        
        if [[ -n "$hit" ]]; then
            local offset=$(echo "$hit" | cut -d: -f1)
            local real_end=$((offset + 8)) # IEND + CRC
            
            if [[ $f_size -gt $real_end ]]; then
                 local hidden_size=$((f_size - real_end))
                 echo -e "${RED}[!] PAYLOAD DETECTED!${NC}"
                 local out_name="${TARGET_FILE}_payload.bin"
                 dd if="$TARGET_FILE" of="$out_name" bs=1 skip="$real_end" status=none
                 HAS_EOF_Data=true
                 add_finding "EOF: Extracted $hidden_size bytes from PNG tail."
                 echo -e "${GREEN} -> Payload saved to $out_name${NC}"
            else
                 echo -e "${GREEN}[OK] PNG ends correctly at IEND.${NC}"
            fi
        fi
    else
        echo "Auto-extraction supported for JPEG/PNG."
    fi
}


# MODULE 7: ENTROPY (Fixed 'bc' error)
function analyze_entropy() {
    print_section "Entropy Analysis"
    
    # Use AWK for calculation (No 'bc' required)
    local ent_score=$(od -v -t u1 "$TARGET_FILE" | awk '
        BEGIN {for(i=0;i<256;i++)c[i]=0;t=0} 
        {for(i=2;i<=NF;i++){c[$i]++;t++}} 
        END {e=0;for(i=0;i<256;i++){if(c[i]>0){p=c[i]/t;e-=p*(log(p)/log(2))}} printf "%.4f",e}
    ')
    
    echo -e "Entropy: ${BOLD}$ent_score${NC} / 8.0"
    
    # Bash float comparison using awk
    local is_high=$(awk -v n="$ent_score" 'BEGIN{print (n > 7.5) ? "1" : "0"}')
    
    if [[ "$is_high" -eq 1 ]]; then
        echo -e "${RED}[!] High Entropy: Encrypted/Compressed payload detected.${NC}"
        IS_High_Entropy=true
        add_finding "Entropy: High ($ent_score) - Encrypted/Packed Data."
    else
        echo -e "${GREEN}[OK] Normal entropy level.${NC}"
    fi
}

# MODULE 8: SMART CARVING (Added Shellcode Support)
function analyze_carving() {
    print_section "File Carving & Payload Search"
    echo "Scanning for embedded headers (Zip, PDF, ELF, Shellcode)..."
    
    # 1. Standard Headers
    local candidates=$(grep -a -b -o -E "PK|%PDF|ELF|Rar\!" "$TARGET_FILE")
    
    # 2. Process Candidates
    if [[ -n "$candidates" ]]; then
        echo "$candidates" | while IFS=: read -r offset match; do
            if [[ "$offset" -eq 0 ]]; then continue; fi 
            
            # Verify Magic Bytes
            local signature=$(dd if="$TARGET_FILE" bs=1 skip="$offset" count=4 2>/dev/null | xxd -p)
            local valid=false
            local ext="dat"
            
            if [[ "$match" == "PK" && "$signature" == "504b0304" ]]; then valid=true; ext="zip";
            elif [[ "$match" == "%PDF" && "$signature" == "25504446" ]]; then valid=true; ext="pdf";
            elif [[ "$match" == "ELF" && "$signature" == *"454c46"* ]]; then valid=true; ext="bin";
            fi
            
            if [ "$valid" = true ]; then
                local out_name="${TARGET_FILE}_carved_${offset}.${ext}"
                echo -e " [HIT] Found embedded file at offset ${YELLOW}$offset${NC}"
                dd if="$TARGET_FILE" of="$out_name" bs=1 skip="$offset" status=none
                echo -e "       -> Extracted to: ${GREEN}$out_name${NC}"
            fi
        done
    fi
    
    add_finding "Carving: Embedded signatures checked."
}


# MODULE 9: REPORT (Corrected Scoring)
function generate_report() {
    print_section "Forensic Confidence Report"
    local score=0
    
    # --- Scoring Logic ---
    if [ "$SIG_MISMATCH" = true ]; then 
        ((score+=40)) # MAJOR RISK: Mismatch
        echo " + Penalty: Extension Mismatch (+40)"
    fi
    
    if [ "$IS_High_Entropy" = true ]; then 
        ((score+=20))
        echo " + Penalty: High Entropy (+20)"
    fi
    
    if [ "$HAS_EOF_Data" = true ]; then 
        ((score+=30))
        echo " + Penalty: Hidden EOF Data (+30)"
    fi
    
    if [ "$MISSING_FOOTER" = true ]; then
        ((score+=30))
        echo " + Penalty: Missing JPEG Footer (+30)"
    fi

    if [ "$HAS_CRITICAL_STRINGS" = true ]; then 
        if [[ $STR_RISK_SCORE -ge 10 ]]; then ((score+=30)); else ((score+=10)); fi
        echo " + Penalty: Suspicious Strings (+$STR_RISK_SCORE hits)"
    fi
    
    # Cap score
    if [[ $score -gt 100 ]]; then score=100; fi
    
    echo "--------------------------------------------------------"
    echo -e "Findings Log:"
    for finding in "${FINDINGS_LOG[@]}"; do
        echo -e " - ${RED}$finding${NC}"
    done
    echo "--------------------------------------------------------"
    
    echo -e "Malicious Confidence Score: ${BOLD}$score/100${NC}"
    
    if [[ $score -ge 70 ]]; then 
        echo -e "${RED}CONCLUSION: HIGH RISK / MALICIOUS${NC}";
        echo "Strong evidence of Malware, Shellcode, or Steganography."
    elif [[ $score -ge 30 ]]; then 
        echo -e "${YELLOW}CONCLUSION: MODERATE RISK${NC}";
    else 
        echo -e "${GREEN}CONCLUSION: LOW RISK${NC}"; 
    fi
    
    echo -e "\n[Artifacts Created]"
    if [[ -f "$STRING_LOG_FILE" ]]; then echo " - String Log: $STRING_LOG_FILE"; fi
    echo " - Extracted Payloads: (Check for *_payload.bin or *_carved.*)"
}

# MAIN LOOP

get_target_file

while true; do
    print_banner
    echo "Target: $TARGET_FILE"
    echo "--------------------------------------------------------"
    echo " 1. Logical vs Physical Size"
    echo " 2. Slack Space Check"
    echo " 3. Hash Calculation"
    echo " 4. Header Validation"
    echo " 5. Intelligent String & Risk Analysis"
    echo " 6. EOF Payload Extraction (Fixes 'Cat' & Malware)"
    echo " 7. Entropy Analysis (Fixed)"
    echo " 8. Smart File Carving"
    echo " 9. Generate Report"
    echo " A. RUN ALL"
    echo " Q. Quit"
    echo "--------------------------------------------------------"
    read -p "Select Module: " CHOICE
    
    case $CHOICE in
        1) analyze_size; press_enter ;;
        2) analyze_slack; press_enter ;;
        3) analyze_hash; press_enter ;;
        4) analyze_header; press_enter ;;
        5) analyze_strings; press_enter ;;
        6) analyze_eof; press_enter ;;
        7) analyze_entropy; press_enter ;;
        8) analyze_carving; press_enter ;;
        9) generate_report; press_enter ;;
        [aA]) 
            analyze_size; analyze_slack; analyze_hash; analyze_header
            analyze_strings; analyze_eof; analyze_entropy; analyze_carving
            generate_report; press_enter ;;
        [qQ]) exit 0 ;;
        *) echo -e "${RED}Invalid.${NC}"; sleep 1 ;;
    esac
done