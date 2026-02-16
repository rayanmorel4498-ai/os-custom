mod test_guard;
extern crate alloc;

use redmi_ia::chat::{ChatInterface, MessageParser};

#[test]
fn test_message_parsing() {
    let parser = MessageParser::new();

    let msg1 = parser.parse("Bonjour, comment vas-tu?");
    println!(
        "Message 1 parsed: Intent={:?}, Sentiment={:?}",
        msg1.intent, msg1.sentiment
    );

    let msg2 = parser.parse("C'est terrible, quelque chose ne fonctionne pas");
    println!(
        "Message 2 parsed: Intent={:?}, Sentiment={:?}",
        msg2.intent, msg2.sentiment
    );

    let msg3 = parser.parse("Peux-tu aider avec optimisation?");
    println!(
        "Message 3 parsed: Intent={:?}, Sentiment={:?}",
        msg3.intent, msg3.sentiment
    );
}

#[test]
fn test_chat_interface_with_parsing() {
    let chat = ChatInterface::new();

    let conv_id = chat.create_conversation();
    println!("Created conversation: {}", conv_id);

    let response1 = chat.send_message("Bonjour!".into());
    println!("Response 1: {:?}", response1);

    let response2 = chat.send_message("Comment fonctionne l'IA?".into());
    println!("Response 2: {:?}", response2);

    let info = chat.get_active_conversation_info();
    println!("Conversation info: {:?}", info);
}

#[test]
fn test_embeddings() {
    let chat = ChatInterface::new();

    let _conv_id = chat.create_conversation();

    chat.send_message("Bonjour, je veux optimiser mon téléphone".into());
    chat.send_message("Comment améliorer les performances?".into());
    chat.send_message("Salut, peux-tu m'aider?".into());

    let results = chat.search_conversation("optimisation du système");
    println!("Search results count: {}", results.len());
}
