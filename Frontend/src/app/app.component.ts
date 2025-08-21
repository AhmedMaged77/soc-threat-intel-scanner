import { Component} from '@angular/core';
import { ScanComponent } from './components/scan/scan.component';

@Component({
  selector: 'app-root',
  standalone: true,
  imports: [ScanComponent],
  templateUrl: './app.component.html',
  styleUrls: ['./app.component.css']
})
export class AppComponent {

}
