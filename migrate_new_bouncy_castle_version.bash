#!/bin/bash

if [ "$#" -ne 2 ]; then
    echo "Usage: $0 <BCFIPSVersion> <PQCAddonVersion>"
    exit 1
fi

projectVersion=$1
pqcVersion=$2
fileName="bc-fips-$projectVersion-sources.jar"
fileNamePQC="bcpqc-addon-fips-$pqcVersion-sources.jar"
url="https://downloads.bouncycastle.org/fips-java/$fileName"
urlPQC="https://downloads.bouncycastle.org/fips-java/$fileNamePQC"
dir=$PWD
cd ../bc-test-data || exit

git pull

cd /tmp || exit
mkdir bcfips-migration
cd bcfips-migration
echo "Download file $url"
wget $url
echo "Unzip file $fileName"
unzip $fileName
rm $fileName
cd /tmp || exit
mkdir bcfips-pqcadddon-migration
cd bcfips-pqcadddon-migration
echo "Download file $urlPQC"
wget $urlPQC
echo "Unzip file $fileNamePQC"
unzip $fileNamePQC
rm $fileNamePQC

cd $dir || exit
echo "Begin migration"
sed -i "s/^version='.*'/version='$projectVersion'/" build.gradle

#migrate core files
cp -r /tmp/bcfips-migration/org/bouncycastle/MARKER src/main/resources/com/distrimind/bcfips
rm /tmp/bcfips-migration/org/bouncycastle/MARKER
rm -r src/main/resources/META-INF
cp -r /tmp/bcfips-migration/META-INF src/main/resources
rm -r src/main/java/com/distrimind/bcfips
cp -r /tmp/bcfips-migration/org/bouncycastle src/main/java/com/distrimind
cp -r /tmp/bcfips-pqcadddon-migration/org/bouncycastle src/main/java/com/distrimind
mv src/main/java/com/distrimind/bouncycastle src/main/java/com/distrimind/bcfips
rm -Rf /tmp/bcfips-migration
rm -Rf /tmp/bcfips-pqcadddon-migration


find . -type f ! -name "migrate_new_bouncy_castle_version.bash" -exec sed -i 's/org\.bouncycastle/com\.distrimind\.bcfips/g' {} +
find . -type f ! -name "migrate_new_bouncy_castle_version.bash" -exec sed -i 's/org\/bouncycastle/com\/distrimind\/bcfips/g' {} +
find . -type f ! -name "migrate_new_bouncy_castle_version.bash" -exec sed -i 's/org\.bouncycastle/com\.distrimind\.bcfips/g' {} +

echo "Migration OK"
echo "Do not forget to alter com.distrimind.bcfips.crypto.fips.FipsStatus"
