#!/usr/bin/env zsh

echo "getting service auth......"
curl \
--silent \
--show-error \
--url 'https://raw.githubusercontent.com/fluggo/aws-service-auth-reference/master/service-auth.json' \
> ./scripts/service-auth.json

echo "getting permissions set from service auth......"
cat ./scripts/service-auth.json  \
| jq --raw-output '
  .[]
  | {service: .servicePrefix} + (.actions[] | {action: .name})
  | "\(.service):\(.action)"
'\
> ./scripts/permissions.txt

echo "adding new permissions to cloudtracker data....."
# Loop through each line in fileA
while IFS= read -r line
do
  # Check if the line exists in fileB
  if ! grep -Fxq "$line" ./cloudtracker/data/aws_api_list.txt; then
    # If the line is not found, append it to fileB
    echo "$line" >> ./cloudtracker/data/aws_api_list.txt
  fi
done < ./scripts/permissions.txt

sort ./cloudtracker/data/aws_api_list.txt -o ./cloudtracker/data/aws_api_list.txt

rm ./scripts/service-auth.json ./scripts/permissions.txt

echo "Script completed."

