use crate::AuraResult;

pub struct Guardrail;

impl Guardrail {
    /// وظيفة الفحص: بترجع true لو الأمر أمان، و false لو فيه خطر
    pub fn check_command(command: &str) -> bool {
        // قائمة الكلمات المحظورة (Blacklist)
        let blacklist = vec![
            "rm -rf",      // مسح شامل
            "sudo rm",     // مسح بصلاحيات أدمن
            "mkfs",        // فورمات للهارد
            "dd if=",      // كتابة مباشرة على الديسك (ممكن تبوظ السيستم)
            ":(){ :|:& };:", // قنبلة فورك (Fork Bomb) بتهنج الجهاز
            "chmod -R 777 /", // فتح صلاحيات السيستم كله (خطر أمني)
            "shutdown",    // قفل الجهاز فجأة
        ];

        let cmd_lower = command.to_lowercase();

        for forbidden in blacklist {
            if cmd_lower.contains(forbidden) {
                return false; // خطر!
            }
        }

        true // الأمر يبدو آمناً
    }
}
