# jpico ReadMe

The Pico project is liberating humanity from passwords. See https://www.mypico.org.

jpico is a Java support library for creating Pico clients and servers. It's used by android-pico, amongst other projects.

## Documentation

For details on the internal classes and structure of the code, see:

https://docs.mypico.org/developer/jpico/

If you want to build all the Pico components from source in one go, without having to worry about the details, see:

https://github.com/mypico/pico-build-all

## Install

To build jpico you'll need to install a JDK, and and a couple of other dependencies:
- openjdk-8-jdk
- ant
- libhamcrest-java
- libemma-java

You can then build jpico at the command line using the following commands.

```
export JAVA_TOOL_OPTIONS=-Dfile.encoding=UTF8
ant compileTest dist
```

This will leave an jar archive at `dist/lib/JPico.jar`.

If you're using jpico with android-pico, it's already included as a submodule of android-pico and will be built automatically when you build android-pico.

## License

jpico is released under the AGPL licence. Read COPYING for information.

There is an older BSD-licenced version of the code available at https://github.com/mypico/jpico-bsd

## Contributing

We welcome comments and contributions to the project. If you're interested in contributing please see here: https://get.mypico.org/cla/

## Contact and Links

More information can be found at: https://mypico.org

The Pico project team at time of release:
 * Frank Stajano (PI)
 * David Llewellyn-Jones
 * Claudio Dettoni
 * Seb Aebischer
 * Kat Krol

You can get in contact with us at team@cambridgeauthentication.com

We thank the European Research Council (ERC) for funding the Pico research through grant StG 307224 (Pico).
