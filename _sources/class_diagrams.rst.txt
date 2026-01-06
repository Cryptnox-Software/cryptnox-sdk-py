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

.. graphviz::
   :caption: Complete card module class hierarchy

   digraph card_module {
      rankdir=TB;
      node [shape=box, style="rounded", fontsize=10, color=black, fontcolor=black];
      edge [arrowsize=0.7, color=black];
      
      // Base abstract class
      Base [label="<<abstract>>\nBase\n─────────────────\n+ serial_number\n+ applet_version\n+ connection\n─────────────────\n+ verify_pin()\n+ sign()\n+ derive()\n+ get_public_key()\n..."];
      
      // Concrete card implementations
      BasicG1 [label="BasicG1\n─────────────────\nBasic G1 Card\n─────────────────\n+ generate_seed()\n+ load_seed()\n+ dual_seed_**()"];
      
      Nft [label="Nft\n─────────────────\nNFT Card\n─────────────────\n+ slot operations\n+ RSA operations"];
      
      // Support classes
      UserData [label="UserData\n─────────────────\n+ read()\n+ write()", fontsize=9];
      
      CustomBits [label="CustomBits\n─────────────────\n+ read()\n+ write()", fontsize=9];
      
      Authenticity [label="authenticity\n(module)\n─────────────────\n+ genuine_check()", fontsize=9];
      
      // Inheritance
      Base -> BasicG1;
      Base -> Nft;
      
      // Composition relationships
      Base -> UserData [style=dashed, arrowhead=diamond, label="has"];
      Base -> CustomBits [style=dashed, arrowhead=diamond, label="has"];
   }

Exception Hierarchy
-------------------

The SDK defines a custom exception hierarchy for different error scenarios:

.. graphviz::
   :caption: Exception class hierarchy (expanded view)

   digraph exceptions {
      rankdir=LR;
      nodesep=0.3;
      ranksep=1.5;
      size="20,14";
      node [shape=box, style="rounded", fontsize=12, color=black, fontcolor=black];
      edge [arrowsize=0.8, color=black];
      
      // Base exception
      CryptnoxException [fontsize=14, label="CryptnoxException\n(Base)"];
      
      // All child exceptions
      CardException;
      CardClosedException;
      CardNotBlocked;
      CardTypeException;
      CertificateException;
      ConnectionException;
      DataException;
      DataValidationException;
      DerivationSelectionException;
      EOSKeyError;
      FirmwareException;
      GenericException;
      GenuineCheckException;
      InitializationException;
      KeyAlreadyGenerated;
      KeyGenerationException;
      KeySelectionException;
      PinAuthenticationException;
      PinException;
      PukException;
      ReadPublicKeyException;
      ReaderException;
      SecureChannelException;
      SeedException;
      SoftLock;
      
      // All edges from base
      CryptnoxException -> CardException;
      CryptnoxException -> CardClosedException;
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
   }

Enum Classes
------------

The SDK uses several enumerations for type safety:

.. graphviz::
   :caption: Enumeration classes

   digraph enums {
      rankdir=TB;
      node [shape=box, style="rounded", fontsize=10, color=black, fontcolor=black];
      edge [arrowsize=0.7, color=black];
      
      // Python base classes
      Enum [label="enum.Enum", fontsize=9];
      IntEnum [label="enum.IntEnum", fontsize=9];
      
      // SDK Enums inheriting from Enum
      AuthType [label="AuthType\n─────────\nNO_AUTH = 0\nPIN = 1\nUSER_KEY = 2"];
      Origin [label="Origin\n─────────\nUNKNOWN = 0\nORIGINAL = 1\nFAKE = 2"];
      SeedSource [label="SeedSource\n─────────\nNO_SEED\nSINGLE\nEXTENDED\nEXTERNAL\nINTERNAL\nDUAL\nWRAPPED"];
      
      // SDK Enums inheriting from IntEnum
      Derivation [label="Derivation\n─────────\nCURRENT_KEY\nDERIVE\nDERIVE_AND_MAKE_CURRENT\nPINLESS_PATH"];
      KeyType [label="KeyType\n─────────\nK1 = 0x00\nR1 = 0x10"];
      SlotIndex [label="SlotIndex\n─────────\nEC256R1 = 0x01\nRSA = 0x02\nFIDO = 0x03"];
      
      // Inheritance relationships
      Enum -> AuthType;
      Enum -> Origin;
      Enum -> SeedSource;
      IntEnum -> Derivation;
      IntEnum -> KeyType;
      IntEnum -> SlotIndex;
   }

Connection Components
---------------------

Classes related to card connection and communication:

.. graphviz::
   :caption: Connection and Reader classes

   digraph connection_components {
      rankdir=TB;
      node [shape=box, style="rounded", fontsize=10, color=black, fontcolor=black];
      edge [arrowsize=0.7, color=black];
      
      // Python base classes
      ContextDecorator [label="contextlib.ContextDecorator", fontsize=9];
      ABCMeta [label="abc.ABCMeta\n(metaclass)", fontsize=9];
      
      // Connection class
      Connection [label="Connection\n─────────────────\n+ index: int\n+ debug: bool\n+ remote: bool\n+ session_public_key: str\n─────────────────\n+ send_apdu()\n+ send_encrypted()\n+ disconnect()\n+ remote_read()"];
      
      // Reader abstract class
      Reader [label="<<abstract>>\nReader\n─────────────────\n# _connection\n─────────────────\n+ connect() «abstract»\n+ send() «abstract»\n+ bool()"];
      
      // Inheritance
      ContextDecorator -> Connection;
      ABCMeta -> Reader [style=dashed, label="metaclass"];
   }

Custom Architecture Diagram
----------------------------

The following diagram shows the high-level architecture of the SDK:

.. graphviz::
   :caption: Cryptnox SDK Architecture

   digraph cryptnox_architecture {
      rankdir=LR;
      node [shape=box, style="rounded", color=black, fontcolor=black];
      edge [color=black];
      
      // Main components
      User [label="User Application"];
      Factory [label="Factory\n(get_card)"];
      Reader [label="Reader"];
      Connection [label="Connection"];
      Card [label="Card Classes\n(Base, BasicG1, Nft)"];
      
      // Utilities
      CryptoUtils [label="Crypto Utils"];
      BinaryUtils [label="Binary Utils"];
      
      // External
      SmartCard [label="Smart Card\nHardware"];
      
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
      node [shape=box, style="rounded", color=black, fontcolor=black];
      edge [color=black];
      
      Start [label="Application Request", shape=ellipse];
      Card [label="Card Object"];
      Connection [label="Connection Layer"];
      APDU [label="APDU Command"];
      SmartCard [label="Smart Card"];
      Response [label="Card Response"];
      Process [label="Process Response"];
      Result [label="Return Result", shape=ellipse];
      
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
      node [shape=box, style="rounded", color=black, fontcolor=black];
      edge [color=black];
      
      GetCard [label="get_card()", shape=ellipse];
      Detect [label="Detect Card Type"];
      Select [label="Select Applet"];
      Serial [label="Get Serial Number"];
      SessionKey [label="Get Session Key"];
      Instantiate [label="Instantiate Card Class"];
      Ready [label="Card Ready", shape=ellipse];
      
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

.. graphviz::
   :caption: Reader implementations (NfcReader and SmartCard reader)

   digraph reader_hierarchy {
      rankdir=TB;
      node [shape=box, style="rounded", fontsize=10, color=black, fontcolor=black];
      edge [arrowsize=0.7, color=black];
      
      // Base abstract class
      Reader [label="<<abstract>>\nReader\n─────────────────\n# _connection\n─────────────────\n+ connect() «abstract»\n+ send() «abstract»\n+ bool()"];
      
      // Concrete implementations
      NfcReader [label="NfcReader\n─────────────────\nxantares/nfc-binding\n─────────────────\n+ connect()\n+ send()"];
      SmartCardReader [label="SmartCard\n─────────────────\npyscard/smartcard\n─────────────────\n+ connect()\n+ send()"];
      
      // Reader module exceptions
      ReaderException [label="ReaderException", fontsize=9];
      CardException [label="CardException", fontsize=9];
      ConnException [label="ConnectionException", fontsize=9];
      
      // Inheritance
      Reader -> NfcReader;
      Reader -> SmartCardReader;
      
      // Group exceptions
      subgraph cluster_exceptions {
         label="Reader Module Exceptions";
         style=dashed;
         fontsize=9;
         color=black;
         fontcolor=black;
         ReaderException; CardException; ConnException;
      }
   }

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
