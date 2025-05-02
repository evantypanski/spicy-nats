 signature dpd_nats {
     ip-proto == tcp
     payload /^(CONNECT|INFO)/
     enable "NATS"
 }
