all: mod_authn_mongodb.la

APR_MONGO=/src/httpd/apr-mongo-c-driver/src

APR_CFLAGS=`/usr/local/apache2/bin/apr-1-config --includes --cppflags --cflags`
APR_LIBS=`/usr/local/apache2/bin/apr-1-config --link-ld --libs --ldflags`

mod_authn_mongodb.la: mod_authn_mongodb.c 
	/usr/local/apache2/bin/apxs -c -n mod_authn_mongodb -I ${APR_MONGO} -L /usr/local/apache2/modules -l mongo mod_authn_mongodb.c

install: mod_authn_mongodb.la
	/usr/local/apache2/bin/apxs -i -n mod_authn_mongodb mod_authn_mongodb.la

clean:
	rm *.o *.slo *.lo *.la
	rm -rf .libs

%.o: %.c
	gcc -g -prefer-pic -DDARWIN -DSIGPROCMASK_SETS_THREAD_MASK -no-cpp-precomp  -I${APR_MONGO} -c $< -o $@ ${APR_CFLAGS} 

