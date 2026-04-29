use thoth::core::inference::InferenceEngine;
use thoth::sys::executor::SystemExecutor;
use thoth::security::guardrails::Guardrail;
use thoth::AuraModule; // دي اللي هتحل خطأ الـ new
use std::io::{self, Write};

#[tokio::main]
async fn main() -> thoth::AuraResult<()> {
    let engine = InferenceEngine::new();
    
    println!("--- Aura Linux Assistant ---");
    print!("كيف يمكنني مساعدتك اليوم؟ ");
    io::stdout().flush().unwrap();

    let mut input = String::new();
    io::stdin().read_line(&mut input)?;
    
    // 1. استنتاج الأمر المناسب
    let suggested_cmd = engine.infer_command(input.trim()).await?;
    
    println!("\n[أورا يقترح]: {}", suggested_cmd);

    // 2. فحص الأمان (Guardrails)
    if !Guardrail::check_command(&suggested_cmd) {
        println!("⚠️ خطأ: تم حظر هذا الأمر لدواعي أمنية!");
        return Ok(());
    }

    // 3. طلب موافقة المستخدم
    print!("هل تريد تنفيذ هذا الأمر؟ (y/n): ");
    io::stdout().flush().unwrap();
    
    let mut confirmation = String::new();
    io::stdin().read_line(&mut confirmation)?;

    if confirmation.trim().to_lowercase() == "y" {
        println!("جاري التنفيذ...\n");
        
        // 4. التنفيذ الحقيقي
        match SystemExecutor::execute(&suggested_cmd) {
            Ok(output) => {
                println!("--- النتيجة ---");
                println!("{}", output);
            }
            Err(e) => println!("فشل التنفيذ: {}", e),
        }
    } else {
        println!("تم إلغاء العملية.");
    }

    Ok(())
}
