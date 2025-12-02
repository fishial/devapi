#!/usr/bin/env bash

set -euo pipefail

DEPENDENCIES=( bc curl jq seq )

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

    -k, --key-id
        Client key ID.

    -s, --key-secret
        Client key secret.

OUTPUT

    A program could produce an output similar to this:

        Fishial Recognition has found 1 fish on the picture.

        Fish 1 [137,326 758,495] is:
          - Roach / Rutilus rutilus [certainty 97.00%]
          - Rudd / Scardinius erythrophthalmus [certainty 10.0%]

    Which means that:

        - there is only one fish on that picture
        - a bounding box for a detected fish is defined by two opposite corners
          at points (137, 326) and (758, 495)
        - two species have been matched, roach and rudd, with certainty 97%
          and 10%, respectively (mind that they do not necessarily sum up to
          100%)

EXAMPLES

    recognize_fish --help
    recognize_fish -h

        Prints this message.

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

#### OBTAIN TOKEN ####

echo "Obtaining authorization token..."
echo

D=$(cat <<JSON
  {
    "client_id": "$KEY_ID",
    "client_secret": "$KEY_SECRET"
  }
JSON
)

R=$(
curl --request POST \
  --silent \
  --url "https://api-recognition.fishial.ai/v2/auth" \
  --header 'Content-Type: application/json' \
  --data "$D"
)

AUTH_TOKEN=$(extract_from_json '.access_token' "$R")

if [[ "$AUTH_TOKEN" == 'null' ]]; then
  echo "Authentication has failed!"
  echo "Make sure that API credentials are valid."
  exit 1
fi

AUTH="Authorization: Bearer $AUTH_TOKEN"

echo "Access token: $AUTH_TOKEN"
echo

#### RUN RECOGNITION ####

echo "Requesting fish recognition..."

R=$(
curl --request POST \
  --silent \
  --url "https://api-recognition.fishial.ai/v2/recognize" \
  --header "$AUTH" \
  --header "Content-Type: application/octet-stream" \
  --data-binary "@${PICTURE}"
)

OK=$(extract_from_json '.ok' "$R")
ERROR=$(extract_from_json '.error' "$R")

if [[ "$OK" != 'true' ]]; then
  echo
  echo "Fishial Recognition has failed to recognize the picture!"
  echo "$ERROR"
  exit 1
fi

#### PRINT RESULTS ####

FISH_COUNT=$(extract_from_json '.objects | length' "$R")

echo
echo "Fishial Recognition has found $FISH_COUNT fish on the picture."

if [[ "$FISH_COUNT" -eq 0 ]]; then
  exit 0
fi

for i in $(seq $FISH_COUNT); do
  FISH_DATA=$(extract_from_json ".objects[$(expr $i - 1)]" "$R")

  POINT1=$(extract_from_json '.bbox[0:2] | join(",")' "$FISH_DATA")
  POINT2=$(extract_from_json '.bbox[2:4] | join(",")' "$FISH_DATA")

  echo
  echo "Fish $i [$POINT1 $POINT2] is:"

  for j in $(seq $(extract_from_json '.species | length' "$FISH_DATA")); do
    SPECIES_MATCH=$(extract_from_json ".species[$(expr $j - 1)]" "$FISH_DATA")
    SPECIES_ID=$(extract_from_json ".id" "$SPECIES_MATCH")
    CERTAINTY1=$(extract_from_json ".certainty" "$SPECIES_MATCH")
    CERTAINTY=$(bc <<<"100 * $CERTAINTY1")

    SPECIES_DEFN=$(extract_from_json ".definitions[\"$SPECIES_ID\"]" "$R")
    SPECIES_NAME_SCI=$(extract_from_json ".scientificName" "$SPECIES_DEFN")
    SPECIES_NAME_ENG=$(extract_from_json ".commonName" "$SPECIES_DEFN")

    echo "  - $SPECIES_NAME_ENG / $SPECIES_NAME_SCI [certainty $CERTAINTY%]"
  done
done
