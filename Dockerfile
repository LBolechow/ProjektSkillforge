FROM openjdk:17-jdk-alpine


WORKDIR /app

COPY target/ProjektSkillforge-0.0.1-SNAPSHOT.jar aplikacja.jar

EXPOSE 8080

ENTRYPOINT ["java", "-jar", "aplikacja.jar"]