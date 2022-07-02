#!/usr/bin/env bash

set -euo pipefail

DEPENDENCIES=( basename curl file grep jq openssl seq wc )

print_help()
{
  cat <<HELP

    ---- Fishial Recognition TM command line tool. ----

REQUIREMENTS

    Following tools must be installed in order to run this program:

        ${DEPENDENCIES[*]}

USAGE

    recognize_fish <options> <picture-file>

    Note: this tool is not production grade.  It lacks proper error checks, etc.

OPTIONS

    -h, --help
        Prints this message and exits.

    -i, --identify
        Identifies picture metadata and exits without performing fish
        recognition.

    -k, --key-id
        Client key ID.

    -s, --key-secret
        Client key secret.

EXAMPLES

    recognize_fish --help
    recognize_fish -h

        Prints this message.

    recognize_fish --identify fishpic.jpg
    recognize_fish -i fishpic.jpg

        Prints metadata of fishpic.jpg.

    recognize_fish --key-id=abc123 --key-secret=abcd1234 fishpic.jpg
    recognize_fish -k abc123 -s abcd1234 fishpic.jpg

        Requests recognition of fishes pictured on fishipic.jpg.
        Client key "abc123" with secret "abcd1234" will be used.

HELP
}

#### HELPERS ####

err()
{
    echo "$1"
    echo "In order to learn more, run: recognize_fish --help"
    exit 1
}

extract_from_json()
{
  jq --raw-output "$1" <<<"$2"
}



#### ENTRY POINT ####

#### PARSE ARGUMENTS ####

while test $# -gt 0
do
  case "$1" in
    -h|--help)
      print_help
      exit 0
      ;;
    -i|--identify)
      ONLY_IDENTIFY=1
      shift
      ;;
    --key-id=*)
      KEY_ID="${1#*=}"
      shift
      ;;
    -k)
      KEY_ID="$2"
      shift
      shift
      ;;
    --key-secret=*)
      KEY_SECRET="${1#*=}"
      shift
      ;;
    -s)
      KEY_SECRET="$2"
      shift
      shift
      ;;
    *)
      PICTURE="$1"
      shift
      ;;
  esac
done

#### CHECK ARGUMENTS ####

if ! [[ -f $PICTURE ]]; then
  err "No picture file has been specified."
fi

#### CHECK DEPENDENCIES ####

for dep in ${DEPENDENCIES[*]}; do
  if ! which -s "$dep"; then
    err "Unsatisfied dependency: $dep"
  fi
done

#### IDENTIFY METADATA ####

echo "Identifying picture metadata..."

NAME="$(basename -- "$PICTURE")"
MIME="$(file --mime-type -b "$PICTURE")"
SIZE="$(wc -c < "$PICTURE" | grep -oE '\d+')"
CSUM="$(openssl dgst -md5 -binary < "$PICTURE" | openssl enc -base64)"

echo
echo "  file name: $NAME"
echo "  MIME type: $MIME"
echo "  byte size: $SIZE"
echo "   checksum: $CSUM"
echo

#### CONDITIONAL EXIT ####

if ! [[ -z ${ONLY_IDENTIFY+x} ]]; then
  exit 0
fi

#### OBTAIN TOKEN ####

echo "Obtaining auth token..."

D=$(cat <<JSON
  {
    "client_id": "$KEY_ID",
    "client_secret": "$KEY_SECRET"
  }
JSON
)

R=$(
curl --request POST \
  --insecure \
  --silent \
  --url https://api-users.fishial.ai/v1/auth/token \
  --header 'Content-Type: application/json' \
  --data "$D"
)

AUTH_TOKEN=$(extract_from_json '.access_token' "$R")
AUTH="Authorization: Bearer $AUTH_TOKEN"

echo "Access token: $AUTH_TOKEN"

#### OBTAIN UPLOAD URL ####

echo "Obtaining upload url..."

D=$(
cat <<JSON
{
  "blob": {
    "filename": "$NAME",
    "content_type": "$MIME",
    "byte_size": $SIZE,
    "checksum": "$CSUM"
  }
}
JSON
)

R=$(
curl --request POST \
  --insecure \
  --silent \
  --url https://api.fishial.ai/v1/recognition/upload \
  --header "$AUTH" \
  --header 'Content-Type: application/json' \
  --header 'Accept: application/json' \
  --data "$D"
)

SIGNED_ID=$(extract_from_json '.["signed-id"]' "$R")
UPLOAD_URL=$(extract_from_json '.["direct-upload"]["url"]' "$R")
CONTENT_DISPOSITION=$(extract_from_json '.["direct-upload"]["headers"]["Content-Disposition"]' "$R")

#### UPLOAD FILE ####

echo "Uploading picture to the cloud..."

curl --request PUT \
  --insecure \
  --silent \
  --url "$UPLOAD_URL" \
  --header "Content-Disposition: $CONTENT_DISPOSITION" \
  --header "Content-Md5: $CSUM" \
  --header "Content-Type:" \
  --data-binary "@${PICTURE}"

#### RUN RECOGNITION ####

echo "Requesting fish recognition..."

R=$(
curl --request GET \
  --insecure \
  --silent \
  --url "https://api.fishial.ai/v1/recognition/image?q=$SIGNED_ID" \
  --header "$AUTH"
)

FISH_COUNT=$(extract_from_json '.results | length' "$R")

#### PRINT RESULTS ####

echo
echo "Fishial Recognition found $FISH_COUNT fish(es) on the picture."

if [[ "$FISH_COUNT" -eq 0 ]]; then
  exit 0
fi

for i in $(seq $FISH_COUNT); do
  FISH_DATA=$(extract_from_json ".results[$(expr $i - 1)]" "$R")

  echo
  echo "Fish $i is:"

  for j in $(seq $(extract_from_json '.species | length' "$FISH_DATA")); do
    SPECIES_DATA=$(extract_from_json ".species[$(expr $j - 1)]" "$FISH_DATA")
    SPECIES_NAME=$(extract_from_json ".name" "$SPECIES_DATA")
    ACCURACY=$(extract_from_json ".accuracy" "$SPECIES_DATA")

    echo "  - $SPECIES_NAME [accuracy $ACCURACY]"
  done
done
