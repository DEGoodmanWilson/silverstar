FROM degoodmanwilson/luna:5.0.0

MAINTAINER D.E. Goodman-Wilson

EXPOSE 8080
WORKDIR /app
ADD . /app
RUN sudo chown -R conan .
RUN ls
RUN conan install . > /dev/null
RUN cmake . > /dev/null
RUN cmake --build . > /dev/null
CMD ["./bin/silverstar"]
