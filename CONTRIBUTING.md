# Contributing Guidelines

Contributions of any kind are warmly welcomed.

You can contribute with reviews, fixes, improvements, optimizations, enhancements, validation tasks, documentation (usage, design, methodology...), tooling...

Suggested contributions:

- Port to one other operating system.
- Add crypto algorithm.
- Add testcase.

## Team organization

- [Steve Wol](https://github.com/stuTcUPw): Development Lead

## How To Contribute

For any contribution to this project, you should:

- Submit an issue describing your proposed contribution
- Wait for a feedback from the code owner and agree with him on the "what" and "how" to produce it
- Fork the repository, develop, test, review and santize your contribution
- Submit a pull request to have your contribution validated, integrated in the main branch and published.

Contributions must comply with a few good practices and common-sense rules to keep the code as readable and maintainable as possible.

The design and implementation can be challenged and modified, but with performances, efficiency and code quality in mind.

The existing code style and coding rules must be followed when fixing, modifying the existing code base.

## Elements Of Design And Implementation

Luna Crypto Provider is written in C code. It is based on the Luna Universal Client PKCS#11 library and/or Functional Module (PQC FM).
It does rely on third-party components Open SSL v3.2.1, liboqs v0.10.0. For PQC algorithms, it is derived from oqs-provider v0.6.0.

Some design and implementation principles are applied to improve usability:

- Luna Crypto Provider is thread-safe.

## Code style and quality

Code is produced using common C/C++ code style (see [here](https://isocpp.github.io/CppCoreGuidelines/CppCoreGuidelines)).

Code can be edited using [Visual Studio Code](https://code.visualstudio.com/download). It is pretty-printed using the [Better C++ Syntax"](https://marketplace.visualstudio.com/items?itemName=jeff-hykin.better-cpp-syntax) extension of Visual Studio Code.

Code style presentation rules are enhanced with the following rules:

- Indentation should follow existing code (typically four spaces in C code, two spaces in shell scripts, no tabs except in makefiles)

- Use of long identifiers to help cognitive efforts and reduce the need for embedded comments.

- One parameter per line on function declarations and calls.

Code quality is checked using:

- Embedded assertions (that are checked even in release mode without any impact on the functions requiring raw performances).

- Sanitization flags (that are set only when debugging the application).

- SAST tools:

  - Coverity

    - Use of agressive mode.

    - No use of any coding style (MISRA...).

  - Sonarqube

    - The following issues are deliberately ignored:

      - c:CommentedCode / cpp:CommentedCode
        - Description: "Sections of code should not be commented out"
        - Rationale:
          - Comments are always considered as useful, including for presentation formatting purposes.

      - c:PPIncludeNotAtTop / cpp:PPIncludeNotAtTop
        - Description: "#include directives in a file should only be preceded by other preprocessor directives or comments"
        - Rationale:
          - This rule raises some issues with "extern C" statements.

      - c:SingleGotoOrBreakPerIteration / cpp:SingleGotoOrBreakPerIteration
        - Description: "Loops should not have more than one "break" or "goto" statement"
        - Rationale:
          - This is a recommendation to improve code readibility; however, it it sometimes relevant to infringe this rule.

      - S107 / cpp:S107

        - Description: "Functions should not have too many parameters"
        - Rationale:
          - This is a recommendation to manage code complexity; however, it it sometimes relevant to infringe this rule.

      - S134 / cpp:S134
        - Description: "Control flow statements "if", "for", "while", "switch" and "try" should not be nested too deeply"
        - Rationale:
          - This is a recommendation to manage code complexity; however, it it sometimes relevant to infringe this rule.

      - S859 / cpp:S859
        - Description: "A cast shall not remove any const or volatile qualification from the type of a pointer or reference"
        - Rationale:
          - This rule is relevant but raises too many alerts with the PKCS#11 API.

      - S1199 / cpp:S1199
        - Description: "Nested code blocks should not be used"
        - Rationale:
          - This is sometimes required to solve some compilation warnings when all the declarations are not grouped at the beginning of the main section.

      - cpp:S1231
        - Description: "C-style memory allocation routines should not be used"
        - Rationale:
          - This is sometimes required when using C code in C++ code.

      - cpp:S1699
        - Description: "Constructors and destructors should only use defined methods and fields"
        - Rationale:
          - Sometimes, it's relevant to infringe this rule to overcome some C++ limits.

      - S1820 / cpp:S1820
        - Description: "Structures should not have too many fields"
        - Rationale:
          - This is a recommendation to manage code complexity; however, it it sometimes simpler to have less code to write and maintain, even if it infringes this rule, rather than extending the size of the code.

      - S1905 / cpp:S1905
        - Description: "Redundant casts should not be used"
        - Rationale:
          - This is a recommendation to improve code readibility; however, explicit casting helps to reduce cognitive efforts.

      - cpp:S3656
        - Description: "Member variables should not be "protected""
        - Rationale:
          - This recommendation results in too much complexity while not reducing significantly risks for errors.

      - S3776 / cpp:S3776
        - Description: "Cognitive Complexity of functions should not be too high"
        - Rationale:
          - This is a recommendation to manage code complexity; however, it it sometimes simpler to have less code to write and maintain, even if it infringes this rule, rather than extending the size of the code.

      - cpp:S4963
        - Description: "The "Rule-of-Zero" should be followed"
        - Rationale:
          - Sometimes, default destructors cannot be used because they are too large and thus, thei are rejected at compilation time.

      - cpp:S5008
        - Description: ""void *" should not be used in typedefs, member variables, function parameters or return type"
        - Rationale:
          - /

      - S5028 / cpp:S5028
        - Description: "Macros should not be used to define constants"
        - Rationale:
          - /

      - cpp:S5945
        - Description: "C-style array should not be used"
        - Rationale:
          - /

Code is validated using one or more test scripts implemented in sub-directory 'tests'. That script must not report any error.
