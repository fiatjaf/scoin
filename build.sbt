ThisBuild / scalaVersion        := "3.2.2"
ThisBuild / organization        := "com.fiatjaf"
ThisBuild / homepage            := Some(url("https://github.com/fiatjaf/scoin"))
ThisBuild / licenses            += License.Apache2
ThisBuild / developers          := List(tlGitHubDev("fiatjaf", "fiatjaf"))

ThisBuild / version             := "0.6.1"
ThisBuild / tlSonatypeUseLegacyHost := false

Global / onChangedBuildSource := ReloadOnSourceChanges

lazy val root = tlCrossRootProject.aggregate(scoin)

lazy val scoin = crossProject(JVMPlatform, JSPlatform, NativePlatform)
  .in(file("."))
  .settings(
    name := "scoin",
    description := "The simplest possible multipurpose Bitcoin and Lightning library for Scala Native and Scala JS.",
    libraryDependencies ++= Seq(
      "org.scodec" %%% "scodec-bits" % "1.1.34",
      "org.scodec" %%% "scodec-core" % (if (scalaVersion.value.startsWith("2.")) "1.11.9" else "2.2.0"),
      "com.comcast" %%% "ip4s-core" % "3.2.0",

      "com.lihaoyi" %%% "utest" % "0.8.0" % Test
    ),
    testFrameworks += new TestFramework("utest.runner.Framework")
  )
  .jvmSettings(
    crossScalaVersions := List("2.13.8", "3.2.0"),
    libraryDependencies ++= Seq(
      "fr.acinq.secp256k1" % "secp256k1-kmp-jni-jvm" % "0.6.4",
      "org.bouncycastle" % "bcprov-jdk15to18" % "1.68"
    )
  )
  .jsConfigure { _.enablePlugins(NpmDependenciesPlugin) }
  .jsSettings(
    scalaVersion := "3.2.0",
    libraryDependencies += ("org.scala-js" %%% "scalajs-java-securerandom" % "1.0.0").cross(CrossVersion.for3Use2_13),
    Compile / npmDependencies ++= Seq(
      "@noble/secp256k1" -> "1.7.1",
      "@noble/hashes" -> "1.0.0",
      "@stablelib/chacha" -> "1.0.1",
      "@stablelib/chacha20poly1305" -> "1.0.1"
    ),
    scalaJSLinkerConfig ~= { _.withModuleKind(ModuleKind.CommonJSModule) },
    esPackageManager := Npm
  )
  .nativeSettings(
    scalaVersion := "3.2.0",
    libraryDependencies ++= Seq(
      "com.fiatjaf" %%% "sn-sha256" % "0.4.1",
      "com.fiatjaf" %%% "sn-secp256k1" % "0.5.0",
      "com.fiatjaf" %%% "sn-chacha20poly1305" % "0.2.1"
    )
  )

// we need these things only to run tests on native and js on github actions
ThisBuild / githubWorkflowBuildPreamble ++= Seq(
  WorkflowStep.Run(
    List("git clone https://github.com/bitcoin-core/secp256k1 && cd secp256k1 && ./autogen.sh && ./configure --enable-module-schnorrsig --enable-module-recovery && make && sudo make install && sudo ln -s /usr/local/lib/libsecp256k1* /usr/lib"),
    name = Some("Install libsecp256k1"),
    cond = Some("matrix.project == 'rootNative'"),
  ),
  WorkflowStep.Run(
    List("npm install @noble/secp256k1 @noble/hashes @stablelib/chacha @stablelib/chacha20poly1305"),
    name = Some("Install Node Modules"),
    cond = Some("matrix.project == 'rootJS'"),
  ),
)

// maven magic, see https://github.com/makingthematrix/scala-suffix/tree/56270a#but-wait-thats-not-all
Compile / packageBin / packageOptions += Package.ManifestAttributes("Automatic-Module-Name" -> "scoin")
