lazy val root = project.in(file("."))
  .aggregate(scoin.js, scoin.jvm, scoin.native)

lazy val scoin = crossProject(JVMPlatform, JSPlatform, NativePlatform)
  .in(file("."))
  .settings(
    name := "scoin",
    organization := "com.fiatjaf",
    version := "0.1.0-SNAPSHOT",
    sonatypeProfileName := "com.fiatjaf",
    homepage := Some(url("https://github.com/fiatjaf/scoin")),
    scmInfo := Some(ScmInfo(url("https://github.com/fiatjaf/scoin"), "git@github.com:fiatjaf/scoin.git")),
    licenses += ("Apache-2.0", url("http://www.apache.org/licenses/LICENSE-2.0")),
    developers := List(
      Developer(id="fiatjaf", name="fiatjaf", email="fiatjaf@gmail.com", url=url("https://fiatjaf.com/")),
    ),
    publishMavenStyle := true,
    publishTo := sonatypePublishToBundle.value,
    sonatypeCredentialHost := "s01.oss.sonatype.org",
    scalacOptions ++= Seq("-deprecation", "-feature"),
    libraryDependencies ++= Seq(
      "org.scodec" %%% "scodec-bits" % "1.1.34",
    )
  )
  .jvmSettings(
    crossScalaVersions := List("2.13.8", "3.1.3"),
    libraryDependencies ++= Seq(
      "fr.acinq.secp256k1" % "secp256k1-kmp-jni-jvm" % "0.6.4",
      "org.bouncycastle" % "bcprov-jdk15to18" % "1.68"
    )
  )
  .jsSettings(
    scalaVersion := "3.1.3"
  )
  .nativeSettings(
    scalaVersion := "3.1.3",
    libraryDependencies ++= Seq(
      "com.fiatjaf" %%% "sn-sha256" % "0.3.0",
      "com.fiatjaf" %%% "sn-secp256k1" % "0.2.0"
    )
  )

// maven magic, see https://github.com/makingthematrix/scala-suffix/tree/56270a6b4abbb1cd1008febbd2de6eea29a23b52#but-wait-thats-not-all
Compile / packageBin / packageOptions += Package.ManifestAttributes("Automatic-Module-Name" -> "scoin")
