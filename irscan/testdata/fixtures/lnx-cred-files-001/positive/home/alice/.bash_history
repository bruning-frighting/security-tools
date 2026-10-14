ls -la
cd /var/www
PGPASSWORD=fixtureNotARealSecret psql -h db.internal -U app -d orders
history -c
