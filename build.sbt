ThisBuild / scalaVersion        := "3.1.3"
ThisBuild / organization        := "com.fiatjaf"
ThisBuild / homepage            := Some(url("https://github.com/fiatjaf/scoin"))
ThisBuild / licenses            += License.Apache2
ThisBuild / developers          := List(tlGitHubDev("fiatjaf", "fiatjaf"))

ThisBuild / version             := "0.2.2-SNAPSHOT"
ThisBuild / tlSonatypeUseLegacyHost := false

lazy val root = tlCrossRootProject.aggregate(scoin)

lazy val scoin = crossProject(JVMPlatform, JSPlatform, NativePlatform)
  .in(file("."))
  .settings(
    name := "scoin",
    description := "The simplest possible multipurpose Bitcoin and Lightning library for Scala Native and Scala JS.",
    libraryDependencies ++= Seq(
      "org.scodec" %%% "scodec-bits" % "1.1.34",
      "org.scodec" %%% "scodec-core" % (if (scalaVersion.value.startsWith("2.")) "1.11.9" else "2.2.0"),

      "com.lihaoyi" %%% "utest" % "0.8.0" % Test
    ),
    testFrameworks += new TestFramework("utest.runner.Framework")
  )
  .jvmSettings(
    crossScalaVersions := List("2.13.8", "3.1.3"),
    libraryDependencies ++= Seq(
      "fr.acinq.secp256k1" % "secp256k1-kmp-jni-jvm" % "0.6.4",
      "org.bouncycastle" % "bcprov-jdk15to18" % "1.68"
    )
  )
  .jsConfigure { _.enablePlugins(NpmDependenciesPlugin) }
  .jsSettings(
    scalaVersion := "3.1.3",
    libraryDependencies += ("org.scala-js" %%% "scalajs-java-securerandom" % "1.0.0").cross(CrossVersion.for3Use2_13),
    Compile / npmDependencies ++= Seq(
      "@noble/secp256k1" -> "1.6.3",
      "hash.js" -> "1.1.7",
      "chacha" -> "2.1.0"
    ),
    scalaJSLinkerConfig ~= { _.withModuleKind(ModuleKind.CommonJSModule) }
  )
  .nativeSettings(
    scalaVersion := "3.1.3",
    libraryDependencies ++= Seq(
      "com.fiatjaf" %%% "sn-sha256" % "0.4.1",
      "com.fiatjaf" %%% "sn-secp256k1" % "0.3.1",
      "com.fiatjaf" %%% "sn-chacha20poly1305" % "0.2.1"
    )
  )

// maven magic, see https://github.com/makingthematrix/scala-suffix/tree/56270a6b4abbb1cd1008febbd2de6eea29a23b52#but-wait-thats-not-all
Compile / packageBin / packageOptions += Package.ManifestAttributes("Automatic-Module-Name" -> "scoin")
