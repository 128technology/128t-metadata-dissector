echo "Available filter fields:" > ./available_fields.txt
tshark -G fields | grep 128t | cut -f3 >> ./available_fields.txt
echo "" >> ./available_fields.txt
echo "Full field/type list:" >> ./available_fields.txt
tshark -G fields | grep 128t >> ./available_fields.txt
