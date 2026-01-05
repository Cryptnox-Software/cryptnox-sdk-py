Class Diagrams
==============

**Automatically generated visual documentation of the Cryptnox SDK architecture**

This section provides automatically generated class diagrams for the Cryptnox SDK Python package.
These diagrams are generated directly from the source code and update automatically when the code changes.

📊 **What you'll find here:**

* **Class Hierarchies** - Inheritance relationships between card, exception, and enum classes
* **System Architecture** - High-level component interactions and data flows  
* **Connection Patterns** - Reader and connection class structures
* **Process Flows** - Card initialization and operation sequences

All diagrams are interactive SVG graphics that update automatically with code changes.

Overview
--------

The Cryptnox SDK follows an object-oriented design with a clear class hierarchy. The diagrams below
illustrate the relationships between classes, inheritance structures, and key components.

Card Class Hierarchy
--------------------

The main card classes follow an inheritance pattern with a base abstract class and specific implementations.

.. inheritance-diagram:: cryptnox_sdk_py.card.base.Base cryptnox_sdk_py.card.basic_g1.BasicG1 cryptnox_sdk_py.card.nft.Nft
   :parts: 1
   :top-classes: cryptnox_sdk_py.card.base.Base
   :caption: Card class inheritance hierarchy

Complete Card Module
---------------------

Complete class hierarchy for all card-related classes:

.. inheritance-diagram:: cryptnox_sdk_py.card
   :parts: 1
   :caption: Complete card module class hierarchy

Exception Hierarchy
-------------------

The SDK defines a custom exception hierarchy for different error scenarios:

.. graphviz::
   :caption: Exception class hierarchy (expanded view)

   digraph exceptions {
      rankdir=LR;
      size="16.0, 10.0";
      node [shape=box, style="rounded,filled", fillcolor=lightblue, fontsize=11];
      edge [arrowsize=0.8];
      
      CryptnoxException [fillcolor=lightcoral, fontsize=12];
      
      CryptnoxException -> CardException;
      CryptnoxException -> CardNotBlocked;
      CryptnoxException -> CardTypeException;
      CryptnoxException -> CertificateException;
      CryptnoxException -> ConnectionException;
      CryptnoxException -> DataException;
      CryptnoxException -> DataValidationException;
      CryptnoxException -> DerivationSelectionException;
      CryptnoxException -> EOSKeyError;
      CryptnoxException -> FirmwareException;
      CryptnoxException -> GenericException;
      CryptnoxException -> GenuineCheckException;
      CryptnoxException -> InitializationException;
      CryptnoxException -> KeyAlreadyGenerated;
      CryptnoxException -> KeyGenerationException;
      CryptnoxException -> KeySelectionException;
      CryptnoxException -> PinAuthenticationException;
      CryptnoxException -> PinException;
      CryptnoxException -> PukException;
      CryptnoxException -> ReadPublicKeyException;
      CryptnoxException -> ReaderException;
      CryptnoxException -> SecureChannelException;
      CryptnoxException -> SeedException;
      CryptnoxException -> SoftLock;
      CryptnoxException -> CardClosedException;
   }

Enum Classes
------------

The SDK uses several enumerations for type safety:

.. inheritance-diagram:: cryptnox_sdk_py.enums
   :parts: 1
   :caption: Enumeration classes

Connection Components
---------------------

Classes related to card connection and communication:

.. inheritance-diagram:: cryptnox_sdk_py.connection.Connection cryptnox_sdk_py.reader.Reader
   :parts: 1
   :caption: Connection and Reader classes

Custom Architecture Diagram
----------------------------

The following diagram shows the high-level architecture of the SDK:

.. graphviz::
   :caption: Cryptnox SDK Architecture

   digraph cryptnox_architecture {
      rankdir=LR;
      node [shape=box, style="rounded,filled", fillcolor=lightblue];
      
      // Main components
      User [label="User Application", fillcolor=lightgreen];
      Factory [label="Factory\n(get_card)"];
      Reader [label="Reader"];
      Connection [label="Connection"];
      Card [label="Card Classes\n(Base, BasicG1, Nft)", fillcolor=lightyellow];
      
      // Utilities
      CryptoUtils [label="Crypto Utils", fillcolor=lightgray];
      BinaryUtils [label="Binary Utils", fillcolor=lightgray];
      
      // External
      SmartCard [label="Smart Card\nHardware", fillcolor=orange];
      
      // Relationships
      User -> Factory [label="creates"];
      Factory -> Reader [label="uses"];
      Reader -> Connection [label="creates"];
      Factory -> Card [label="instantiates"];
      Card -> Connection [label="uses"];
      Connection -> SmartCard [label="communicates"];
      Card -> CryptoUtils [label="uses"];
      Card -> BinaryUtils [label="uses"];
   }

Data Flow Diagram
-----------------

The following diagram illustrates the data flow during card operations:

.. graphviz::
   :caption: Card Operation Data Flow

   digraph card_operation_flow {
      rankdir=TB;
      node [shape=box, style="rounded,filled", fillcolor=lightblue];
      
      Start [label="Application Request", shape=ellipse, fillcolor=lightgreen];
      Card [label="Card Object"];
      Connection [label="Connection Layer"];
      APDU [label="APDU Command", fillcolor=lightyellow];
      SmartCard [label="Smart Card", fillcolor=orange];
      Response [label="Card Response", fillcolor=lightyellow];
      Process [label="Process Response"];
      Result [label="Return Result", shape=ellipse, fillcolor=lightgreen];
      
      Start -> Card [label="method call"];
      Card -> Connection [label="send request"];
      Connection -> APDU [label="format"];
      APDU -> SmartCard [label="transmit"];
      SmartCard -> Response [label="receive"];
      Response -> Connection [label="parse"];
      Connection -> Card [label="return data"];
      Card -> Process [label="validate"];
      Process -> Result;
   }

Card Initialization Sequence
-----------------------------

.. graphviz::
   :caption: Card Initialization Process

   digraph card_init {
      rankdir=TB;
      node [shape=box, style="rounded,filled", fillcolor=lightblue];
      
      GetCard [label="get_card()", shape=ellipse];
      Detect [label="Detect Card Type"];
      Select [label="Select Applet"];
      Serial [label="Get Serial Number"];
      SessionKey [label="Get Session Key"];
      Instantiate [label="Instantiate Card Class"];
      Ready [label="Card Ready", shape=ellipse, fillcolor=lightgreen];
      
      GetCard -> Detect;
      Detect -> Select;
      Select -> Serial;
      Serial -> SessionKey;
      SessionKey -> Instantiate;
      Instantiate -> Ready;
   }

Reader Class Hierarchy
----------------------

The SDK supports different types of card readers:

.. inheritance-diagram:: cryptnox_sdk_py.reader
   :parts: 1
   :caption: Reader implementations (NfcReader and SmartCard reader)

Notes on Diagram Generation
----------------------------

**Automatic Updates**: All diagrams on this page are generated automatically from the Python source code
during the Sphinx build process. When you modify the code structure, simply rebuild the documentation to
see updated diagrams.

**Technologies Used**:

* **Sphinx**: Documentation generator
* **sphinx.ext.inheritance_diagram**: For class hierarchy diagrams
* **sphinx.ext.graphviz**: For custom architecture and flow diagrams
* **Graphviz**: Graph visualization software

**Build Requirements**: Make sure Graphviz is installed on your system and available in your PATH.
See the documentation guides for detailed setup instructions.

For Developers
--------------

If you're a developer working on this project and need to regenerate or customize diagrams, please refer to:

* **Developer Guide**: `docs/DEVELOPER_GUIDE_DIAGRAMS.md` - Complete documentation guide

**Quick rebuild command**:

.. code-block:: bash

   cd docs
   sphinx-build -b html . _build/html
