/*
 * Copyright (c) 2012 SnowPlow Analytics Ltd. All rights reserved.
 *
 * This program is licensed to you under the Apache License Version 2.0,
 * and you may not use this file except in compliance with the Apache License Version 2.0.
 * You may obtain a copy of the Apache License Version 2.0 at http://www.apache.org/licenses/LICENSE-2.0.
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the Apache License Version 2.0 is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the Apache License Version 2.0 for the specific language governing permissions and limitations there under.
 */
import sbt._

object Dependencies {
  val resolutionRepos = Seq(
    ScalaToolsSnapshots
  )

  object V {
    val tomcat  = "6.0.33"
    val specs2    = "1.12.1"    
  }

  object Libraries {
    val catalina    = "org.apache.tomcat"          %  "catalina"             % V.tomcat    % "provided"
    val coyote      = "org.apache.tomcat"          %  "coyote"             % V.tomcat    % "provided"
    val specs2      = "org.specs2"                 %% "specs2"               % V.specs2      % "test"
  }
}