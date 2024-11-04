FROM maven:3.9.9 AS build

WORKDIR /app

COPY pom.xml .
COPY src ./src

RUN mvn clean package -DskipTests

FROM openjdk:17-jdk-alpine

WORKDIR /app

COPY --from=build /app/target/ProjektSkillforge-0.0.1-SNAPSHOT.jar aplikacja.jar

ENV SPRING_PROFILES_ACTIVE=docker
EXPOSE 8080

ENTRYPOINT ["java", "-jar", "-Dspring.devtools.restart.enabled=true", "aplikacja.jar"]